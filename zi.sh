#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# Uses user's provided login.html + index.html exactly, bundles into /etc/zivpn-admin/panel.json (immutable)
# Script Owner By: JueHtet
set -e
export LC_ALL=C

clear
echo "=============================================="
echo "   ZIVPN UDP + Admin Panel Auto Installer"
echo "   (Port per User, HWID Note, JSON-embedded UI)"
echo "=============================================="
echo

echo "[0/4] System update & base packages..."
apt-get update -y
apt-get install -y sudo curl wget python3 python3-venv python3-pip sqlite3 ufw conntrack iproute2 iptables openssl e2fsprogs -y || true

########################################
# 1. INSTALL ZIVPN UDP SERVER
########################################
echo
echo "[1/4] Installing ZIVPN UDP..."

systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
mkdir -p /etc/zivpn

echo "Downloading UDP Service..."
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn || true
chmod +x /usr/local/bin/zivpn || true

echo "Downloading default config..."
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || true

echo "Generating cert files..."
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" 1>/dev/null 2>/dev/null || true

sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null || true
sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null || true

cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=no
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo
read -p "Enter ZIVPN passwords separated by commas (Press enter for default 'zi'): " input_config

if [ -z "$input_config" ]; then
  password_list="\"zi\""
else
  password_list=""
  IFS=',' read -r -a arr <<< "$input_config"
  for p in "${arr[@]}"; do
    p_trim="$(echo "$p" | xargs)"
    [ -z "$p_trim" ] && continue
    password_list="${password_list}\"$p_trim\","
  done
  password_list="${password_list%,}"
  [ -z "$password_list" ] && password_list="\"zi\""
fi

# Patch config.json safely with python
python3 - <<PY || true
import json,sys
p="/etc/zivpn/config.json"
try:
    d=json.load(open(p))
except Exception:
    d={}
d.setdefault("auth",{})
d["auth"]["config"]=[${password_list}]
open(p,"w").write(json.dumps(d))
print("Patched",p)
PY

systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service || true

DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
if [ -n "$DEV" ]; then
  iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
fi

ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true
ufw allow 8989/tcp || true

# cleanup old quota chains if present
iptables -t raw -D PREROUTING -p udp --dport 6000:19999 -j ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -F ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -X ZIVPN_QUOTA 2>/dev/null || true

echo "[+] ZIVPN UDP Installed."

########################################
# 2. ADMIN LOGIN SETUP
########################################
echo
echo "[2/4] Configure Admin Panel Login..."

mkdir -p /etc/zivpn-admin
mkdir -p /usr/local/zivpn-admin/panel
mkdir -p /var/lib/zivpn-admin

read -p "Set Admin Panel username (default: admin): " ADMIN_USER
[ -z "$ADMIN_USER" ] && ADMIN_USER="admin"

read -p "Set Admin Panel password (default: admin123): " ADMIN_PASS
[ -z "$ADMIN_PASS" ] && ADMIN_PASS="admin123"

ADMIN_USER_JSON=$(printf '%s' "$ADMIN_USER" | sed 's/\"/\\\"/g')
ADMIN_PASS_JSON=$(printf '%s' "$ADMIN_PASS" | sed 's/\"/\\\"/g')

cat <<EOF > /etc/zivpn-admin/admin.json
{
  "username": "$ADMIN_USER_JSON",
  "password": "$ADMIN_PASS_JSON"
}
EOF

chown root:root /etc/zivpn-admin/admin.json || true
chmod 600 /etc/zivpn-admin/admin.json || true

########################################
# 3. ADMIN PANEL BACKEND (server.py) - serves embedded JSON
########################################
echo
echo "[3/4] Installing ZIVPN Admin Panel (Web UI Backend)..."

if [ ! -d "/usr/local/zivpn-admin/venv" ]; then
  python3 -m venv /usr/local/zivpn-admin/venv
fi

/usr/local/zivpn-admin/venv/bin/pip install --upgrade pip 1>/dev/null 2>/dev/null || true
/usr/local/zivpn-admin/venv/bin/pip install flask 1>/dev/null 2>/dev/null || true

cat <<'PY' > /usr/local/zivpn-admin/server.py
#!/usr/bin/env python3
import os, json, sqlite3, datetime, subprocess
from functools import wraps
from flask import Flask, request, jsonify, redirect, session, Response

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
CONFIG_PATH = "/etc/zivpn/config.json"
ADMIN_FILE = "/etc/zivpn-admin/admin.json"
PANEL_JSON_PATH = "/etc/zivpn-admin/panel.json"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8989
PORT_MIN = 6001
PORT_MAX = 19999

app = Flask(__name__, static_folder=None)
app.secret_key = "zivpn_super_secret_key_change_me"

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE,
            password   TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expire_at  TEXT NOT NULL,
            udp_port   INTEGER UNIQUE,
            hwid       TEXT
        )
    """)
    cur.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if "hwid" not in cols:
        try:
            cur.execute("ALTER TABLE users ADD COLUMN hwid TEXT")
        except Exception:
            pass
    conn.commit()
    conn.close()

def get_admin_creds():
    try:
        with open(ADMIN_FILE,"r") as f:
            d=json.load(f)
        return d.get("username","admin"), d.get("password","admin123")
    except Exception:
        return "admin","admin123"

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def load_panel_html():
    try:
        with open(PANEL_JSON_PATH,"r",encoding="utf-8") as f:
            d=json.load(f)
        return d.get("login.html",""), d.get("index.html","")
    except Exception:
        return "",""

def get_server_ip():
    try:
        ip = subprocess.check_output(["bash","-lc","ip -4 route get 1.1.1.1 | awk '{print $7}' | head -1"], stderr=subprocess.DEVNULL, shell=True).decode().strip()
        if ip: return ip
    except Exception:
        pass
    try:
        ip = subprocess.check_output(["bash","-lc","hostname -I | awk '{print $1}'"], stderr=subprocess.DEVNULL, shell=True).decode().strip()
        if ip: return ip
    except Exception:
        pass
    return "127.0.0.1"

def get_server_stats():
    cpu_percent = None
    mem_total_gb = None
    mem_used_percent = None
    disk_total_gb = None
    disk_used_percent = None
    try:
        load1,_,_ = os.getloadavg()
        cores = os.cpu_count() or 1
        cpu_percent = min(100.0, round(load1/cores*100.0,1))
    except Exception:
        pass
    try:
        meminfo={}
        with open("/proc/meminfo") as f:
            for line in f:
                parts=line.split(":")
                if len(parts)<2: continue
                k=parts[0].strip()
                v=parts[1].strip().split()[0]
                meminfo[k]=float(v)
        total_kb = meminfo.get("MemTotal",0.0)
        avail_kb = meminfo.get("MemAvailable",0.0)
        if total_kb>0:
            mem_total_gb = round(total_kb/(1024*1024),1)
            used_kb = total_kb - avail_kb
            mem_used_percent = round(used_kb/total_kb*100.0,1)
    except Exception:
        pass
    try:
        st=os.statvfs("/")
        total=st.f_frsize*st.f_blocks
        free=st.f_frsize*st.f_bavail
        if total>0:
            disk_total_gb = round(total/(1024**3),1)
            disk_used_percent = round((total-free)/total*100.0,1)
    except Exception:
        pass
    return {"cpu_percent":cpu_percent,"mem_total_gb":mem_total_gb,"mem_used_percent":mem_used_percent,"disk_total_gb":disk_total_gb,"disk_used_percent":disk_used_percent}

def user_to_dict(row):
    try:
        expire_at = datetime.datetime.fromisoformat(row["expire_at"])
    except Exception:
        expire_at = datetime.datetime.utcnow()
    try:
        created_at = datetime.datetime.fromisoformat(row["created_at"])
    except Exception:
        created_at = datetime.datetime.utcnow()
    now = datetime.datetime.utcnow()
    days_left = (expire_at.date() - now.date()).days
    if days_left < 0: days_left = 0
    if expire_at < now:
        status = "Offline"
    elif days_left <= 3:
        status = "Expiring"
    else:
        status = "Online"
    return {"id":row["id"],"username":row["username"],"password":row["password"],"created_at":created_at.strftime("%Y-%m-%d"),"expire_at":expire_at.strftime("%Y-%m-%d"),"day_left":days_left,"status":status,"udp_port":row["udp_port"],"hwid":row["hwid"]}

def sync_config_with_db():
    try:
        conn=get_db(); cur=conn.cursor(); cur.execute("SELECT password, expire_at FROM users"); rows=cur.fetchall(); conn.close()
        passwords=[]; now=datetime.datetime.utcnow()
        for r in rows:
            try:
                expire_at = datetime.datetime.fromisoformat(r["expire_at"])
            except Exception:
                continue
            if expire_at >= now and r["password"] not in passwords:
                passwords.append(r["password"])
        if not os.path.exists(CONFIG_PATH): return
        with open(CONFIG_PATH,"r") as f:
            data=json.load(f)
        auth = data.get("auth",{})
        auth["config"] = passwords if passwords else ["zi"]
        data["auth"] = auth
        with open(CONFIG_PATH,"w") as f:
            json.dump(data,f)
        subprocess.run(["systemctl","restart","zivpn.service"], check=False)
    except Exception as e:
        print("sync_config_with_db error:", e)

def allocate_udp_port():
    conn=get_db(); cur=conn.cursor()
    try:
        cur.execute("SELECT udp_port FROM users WHERE udp_port IS NOT NULL"); rows=cur.fetchall()
    except Exception:
        rows=[]
    conn.close()
    used = {r["udp_port"] for r in rows if r["udp_port"] is not None}
    for p in range(PORT_MIN, PORT_MAX+1):
        if p not in used: return p
    return None

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="GET":
        login_html, _ = load_panel_html()
        if not login_html: return "Login UI not available", 500
        return Response(login_html, mimetype="text/html; charset=utf-8")
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    admin_user, admin_pass = get_admin_creds()
    if username==admin_user and password==admin_pass:
        session["admin_logged_in"]=True
        return redirect("/")
    login_html, _ = load_panel_html()
    return Response(login_html, mimetype="text/html; charset=utf-8"), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    _, index_html = load_panel_html()
    if not index_html: return "Panel UI not available", 500
    return Response(index_html, mimetype="text/html; charset=utf-8")

@app.route("/api/server", methods=["GET"])
@login_required
def api_server_info():
    ip=get_server_ip(); stats=get_server_stats()
    return jsonify({"ip":ip,"panel_port":LISTEN_PORT,"udp_port":5667,"cpu_percent":stats["cpu_percent"],"mem_total_gb":stats["mem_total_gb"],"mem_used_percent":stats["mem_used_percent"],"disk_total_gb":stats["disk_total_gb"],"disk_used_percent":stats["disk_used_percent"]})

@app.route("/api/users", methods=["GET"])
@login_required
def api_list_users():
    conn=get_db(); cur=conn.cursor(); cur.execute("SELECT * FROM users ORDER BY id DESC"); rows=cur.fetchall(); conn.close()
    users=[user_to_dict(r) for r in rows]
    total=len(users); online=sum(1 for u in users if u["status"] in ("Online","Expiring")); offline=sum(1 for u in users if u["status"]=="Offline")
    return jsonify({"total":total,"online":online,"offline":offline,"users":users})

@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    try:
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        expire_date_str = (data.get("expire_date") or "").strip()
        hwid = (data.get("hwid") or "").strip()
        if not username or not password:
            return jsonify({"error":"username and password required"}),400
        udp_port = allocate_udp_port()
        if udp_port is None:
            return jsonify({"error":"no free UDP port available"}),400
        now=datetime.datetime.utcnow(); created_at=now.isoformat()
        if expire_date_str:
            try:
                expire_date=datetime.datetime.strptime(expire_date_str,"%Y-%m-%d")
            except ValueError:
                expire_date=now+datetime.timedelta(days=30)
        else:
            expire_date=now+datetime.timedelta(days=30)
        expire_at = expire_date.replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
        conn=get_db(); cur=conn.cursor()
        try:
            cur.execute("INSERT INTO users (username,password,created_at,expire_at,udp_port,hwid) VALUES (?,?,?,?,?,?)",(username,password,created_at,expire_at,udp_port,hwid or None))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error":"username already exists"}),400
        except sqlite3.OperationalError as e:
            conn.close()
            return jsonify({"error":"database error: "+str(e)}),500
        conn.close()
        sync_config_with_db()
        return jsonify({"success":True,"udp_port":udp_port})
    except Exception as e:
        print("api_create_user unexpected error:", e)
        return jsonify({"error":"internal error: "+str(e)}),500

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_delete_user(user_id):
    conn=get_db(); cur=conn.cursor(); cur.execute("DELETE FROM users WHERE id = ?", (user_id,)); conn.commit(); conn.close(); sync_config_with_db(); return jsonify({"success":True})

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def api_update_user(user_id):
    data = request.get_json(silent=True) or request.form
    password = (data.get("password") or "").strip()
    expire_date_str = (data.get("expire_date") or "").strip()
    fields=[]; params=[]
    if password:
        fields.append("password = ?"); params.append(password)
    if expire_date_str:
        try:
            expire_date = datetime.datetime.strptime(expire_date_str,"%Y-%m-%d")
            expire_at = expire_date.replace(hour=0,minute=0,second=0,microsecond=0).isoformat()
            fields.append("expire_at = ?"); params.append(expire_at)
        except ValueError:
            pass
    if "hwid" in data:
        hwid_val = data.get("hwid"); fields.append("hwid = ?"); params.append(hwid_val if hwid_val is not None and hwid_val != "" else None)
    if not fields:
        return jsonify({"error":"nothing to update"}),400
    params.append(user_id)
    conn=get_db(); cur=conn.cursor(); cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", params); conn.commit(); conn.close(); sync_config_with_db(); return jsonify({"success":True})

@app.route("/api/admin", methods=["POST"])
@login_required
def api_update_admin():
    data = request.get_json(silent=True) or {}
    old_password = (data.get("old_password") or "").strip()
    new_username = (data.get("new_username") or "").strip()
    new_password = (data.get("new_password") or "").strip()
    current_user, current_pass = get_admin_creds()
    if old_password != current_pass:
        return jsonify({"error":"Old password incorrect"}),400
    if not new_username:
        new_username = current_user
    if not new_password:
        new_password = current_pass
    try:
        with open(ADMIN_FILE,"w") as f:
            json.dump({"username":new_username,"password":new_password}, f)
        try:
            os.chmod(ADMIN_FILE,0o600)
        except Exception:
            pass
        return jsonify({"success":True,"username":new_username})
    except Exception as e:
        return jsonify({"error":str(e)}),500

if __name__=="__main__":
    init_db()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
PY

chmod +x /usr/local/zivpn-admin/server.py || true

########################################
# 4. PANEL UI: write the exact login.html and index.html provided by the user,
#    then bundle them into /etc/zivpn-admin/panel.json and protect it.
########################################
echo
echo "[4/4] Writing your provided panel HTML files and bundling into JSON..."

# Write the exact login.html (use your original content)
cat > /usr/local/zivpn-admin/panel/login.html <<'HTML_LOGIN'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: radial-gradient(circle at top, #1f2937 0, #020617 50%, #000 100%);
      color: #e5e7eb;
    }
    .card {
      background: rgba(15,23,42,0.95);
      border-radius: 18px;
      padding: 24px 22px;
      width: 320px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.7);
      border: 1px solid rgba(148,163,184,0.35);
      backdrop-filter: blur(14px);
    }
    h1 {
      margin: 0 0 4px;
      font-size: 1.4rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .logo {
      width: 30px;
      height: 30px;
      border-radius: 999px;
      overflow: hidden;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .logo img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .subtitle {
      font-size: 0.8rem;
      color: #9ca3af;
      margin-bottom: 14px;
    }
    label {
      display: block;
      font-size: 0.75rem;
      color: #9ca3af;
      margin-bottom: 4px;
    }
    input {
      width: 100%;
      background: rgba(15,23,42,0.95);
      border-radius: 10px;
      border: 1px solid rgba(148,163,184,0.5);
      padding: 7px 10px;
      color: #e5e7eb;
      font-size: 0.85rem;
      margin-bottom: 10px;
    }
    .remember-row {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 0.75rem;
      color: #9ca3af;
      margin-bottom: 8px;
    }
    .remember-row input {
      width: auto;
      margin: 0;
    }
    button {
      width: 100%;
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      background: linear-gradient(135deg,#22c55e,#0ea5e9,#a855f7);
      background-size: 200% 200%;
      color: #020617;
      font-weight: 600;
      font-size: 0.9rem;
      box-shadow: 0 14px 28px rgba(0,0,0,0.7);
      animation: loginBtn 4s ease-in-out infinite;
    }
    @keyframes loginBtn {
      0%,100%{background-position:0% 50%;}
      50%{background-position:100% 50%;}
    }
    .muted {
      margin-top: 8px;
      font-size: 0.75rem;
      color: #9ca3af;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>
      <span class="logo">
        <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN">
      </span>
      <span>Admin Login</span>
    </h1>
    <div class="subtitle">Enter the admin username and password from installer output.</div>
    <form method="post" id="login-form">
      <label>Username</label>
      <input name="username" autocomplete="off" required>
      <label>Password</label>
      <input name="password" autocomplete="off" required>
      <label class="remember-row">
        <input type="checkbox" id="rememberMe">
        <span>Save login</span>
      </label>
      <button type="submit">Login</button>
    </form>
    <div class="muted">Protected ZIVPN Admin Panel</div>
  </div>

  <script>
    const userInput = document.querySelector('input[name="username"]');
    const passInput = document.querySelector('input[name="password"]');
    const remember = document.getElementById('rememberMe');
    const form = document.getElementById('login-form');

    window.addEventListener('DOMContentLoaded', () => {
      try {
        const saved = JSON.parse(localStorage.getItem('zivpn_login_save') || 'null');
        if (saved) {
          if (saved.username) userInput.value = saved.username;
          if (saved.password) passInput.value = saved.password;
          remember.checked = true;
        }
      } catch(e) {}
    });

    form.addEventListener('submit', () => {
      if (remember.checked) {
        const payload = {
          username: userInput.value || "",
          password: passInput.value || ""
        };
        localStorage.setItem('zivpn_login_save', JSON.stringify(payload));
      } else {
        localStorage.removeItem('zivpn_login_save');
      }
    });
  </script>
</body>
</html>
HTML_LOGIN

# Write the exact index.html provided by user
cat > /usr/local/zivpn-admin/panel/index.html <<'HTML_INDEX'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Panel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    body {
      margin: 0;
      padding: 0;
      background: radial-gradient(circle at top, #1f2937 0, #020617 45%, #000 100%);
      color: #e5e7eb;
      min-height: 100vh;
      transition: background 0.25s ease, color 0.25s ease;
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px 14px 40px;
    }
    .card {
      background: rgba(15,23,42,0.95);
      border-radius: 18px;
      padding: 20px 18px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.7);
      border: 1px solid rgba(148,163,184,0.35);
      backdrop-filter: blur(14px);
      transition: background 0.25s ease, border-color 0.25s ease;
    }
    h1 {
      font-size: 1.6rem;
      margin: 0 0 10px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .logo {
      display: inline-flex;
      width: 34px;
      height: 34px;
      border-radius: 999px;
      overflow: hidden;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 18px rgba(34,197,94,0.7);
    }
    .logo img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .top-row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 14px;
    }
    .vps-box {
      padding: 10px 12px;
      border-radius: 14px;
      background: rgba(15,23,42,0.95);
      border: 1px solid rgba(148,163,184,0.45);
      flex: 1 1 100%;
      width: 100%;
      box-sizing: border-box;
      transition: background 0.25s ease, border-color 0.25s ease;
    }
    .vps-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: .09em;
      color: #9ca3af;
      margin-bottom: 4px;
    }
    .vps-value {
      font-size: 1rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .muted {
      font-size: 0.75rem;
      color: #9ca3af;
    }
    .stat-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 16px;
    }
    .stat-chip {
      flex: 1 1 80px;
      min-width: 90px;
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(15,23,42,0.95);
      border: 1px solid rgba(148,163,184,0.45);
      font-size: 0.8rem;
      transition: background 0.25s ease, border-color 0.25s ease;
      width: 100%;
      box-sizing: border-box;
    }
    .users-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill,minmax(260px,1fr));
      gap: 10px;
      margin-top: 6px;
    }
    .user-card {
      background: rgba(15,23,42,0.98);
      border-radius: 14px;
      border: 1px solid rgba(55,65,81,0.9);
      padding: 10px 10px;
      font-size: 0.78rem;
      transition: background 0.25s ease, border-color 0.25s ease;
    }
    .footer-icons {
      margin-top: 16px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      font-size: 0.8rem;
      color: #9ca3af;
    }
    .social-icon {
      width: 32px;
      height: 32px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: none;
      background: #111;
      color: #fff;
      font-weight: 700;
    }
    .owner-flag {
      margin-top: 12px;
      font-size: 0.9rem;
      color: #fbbf24;
      font-weight: 700;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>
        <span class="logo">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN">
        </span>
        <span>ZIVPN Admin Panel</span>
      </h1>

      <div class="top-row">
        <div class="vps-box">
          <div class="vps-label">VPS IP</div>
          <div class="vps-value">
            <span id="server-ip">Detecting...</span>
            <span class="pill pill-blue" id="udp-port-pill">UDP :5667</span>
          </div>
          <div class="muted" style="margin-top:4px;">
            Admin Panel: <span id="panel-url"></span>
          </div>
        </div>
      </div>

      <div class="stat-row">
        <div class="stat-chip">
          <div class="stat-label">🧠 CPU</div>
          <div class="stat-value" id="stat-cpu">-</div>
        </div>
        <div class="stat-chip">
          <div class="stat-label">💾 RAM</div>
          <div class="stat-value" id="stat-ram">-</div>
        </div>
        <div class="stat-chip">
          <div class="stat-label">🗄 Storage</div>
          <div class="stat-value" id="stat-disk">-</div>
        </div>
      </div>

      <div style="margin-top:10px">
        <form id="create-form" onsubmit="createUser(event)">
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <input id="username" placeholder="Username" style="padding:8px;border-radius:8px;border:1px solid rgba(148,163,184,0.5)">
            <input id="password" placeholder="Password" style="padding:8px;border-radius:8px;border:1px solid rgba(148,163,184,0.5)">
            <input id="hwid" placeholder="HWID (optional)" style="padding:8px;border-radius:8px;border:1px solid rgba(148,163,184,0.5)">
            <input id="expire_date" type="date" style="padding:8px;border-radius:8px;border:1px solid rgba(148,163,184,0.5)">
            <button style="padding:8px 12px;border-radius:999px;border:none;background:linear-gradient(135deg,#22c55e,#0ea5e9,#a855f7);color:#020617;font-weight:600">➕ Add</button>
          </div>
        </form>
      </div>

      <div id="users-wrap" class="users-grid"></div>

      <div class="footer-icons">
        <span>Contact :</span>
        <div class="social-icon" title="Telegram">TG</div>
        <div class="social-icon" title="Facebook">FB</div>
        <div class="social-icon" title="Messenger">MS</div>
      </div>

      <div class="owner-flag">🔥 Script Owner By: Jue Htet 🔥</div>

    </div>
  </div>

<script>
let serverIpCache=null;
async function fetchServerInfo(){
  try{
    const res=await fetch('/api/server');
    const data=await res.json();
    serverIpCache=data.ip;
    document.getElementById('server-ip').textContent=data.ip;
    document.getElementById('panel-url').textContent=data.ip+':'+data.panel_port;
    document.getElementById('stat-cpu').textContent=data.cpu_percent!=null?data.cpu_percent+'%':'-';
    document.getElementById('stat-ram').textContent=(data.mem_used_percent!=null&&data.mem_total_gb!=null)?data.mem_used_percent+'% of '+data.mem_total_gb+' GB':'-';
    document.getElementById('stat-disk').textContent=(data.disk_used_percent!=null&&data.disk_total_gb!=null)?data.disk_used_percent+'% of '+data.disk_total_gb+' GB':'-';
  }catch(e){
    document.getElementById('server-ip').textContent='Unknown';
  }
}
async function fetchUsers(){
  try{
    const res=await fetch('/api/users');
    if(res.status===401||res.redirected){window.location.href='/login';return;}
    const data=await res.json();
    renderUsers(data);
  }catch(e){}
}
function renderUsers(data){
  const wrap=document.getElementById('users-wrap');
  wrap.innerHTML='';
  (data.users||[]).forEach(u=>{
    const div=document.createElement('div');
    div.className='user-card';
    const portText=u.udp_port!=null?u.udp_port:'-';
    div.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-weight:600">${u.username}</div><div style="font-size:0.8rem;background:rgba(22,163,74,0.12);padding:4px 8px;border-radius:999px">PORT ${portText}</div></div>
      <div style="font-size:0.85rem;margin-bottom:4px">Pass: <strong>${u.password}</strong></div>
      <div style="font-size:0.8rem;color:#9ca3af">HWID: ${u.hwid||'-'}</div>
      <div style="margin-top:8px;display:flex;gap:6px"><button onclick="editUser(${u.id},'${u.username}','${u.password}','${u.expire_at}','${u.hwid||''}')" style="padding:6px;border-radius:8px;border:1px solid rgba(148,163,184,0.5);background:transparent">Edit</button><button onclick="deleteUser(${u.id})" style="padding:6px;border-radius:8px;border:none;background:rgba(239,68,68,0.12);color:#fecaca">Delete</button></div>`;
    wrap.appendChild(div);
  });
}
async function createUser(ev){ev.preventDefault();
  const username=document.getElementById('username').value.trim();
  const password=document.getElementById('password').value.trim();
  const hwid=document.getElementById('hwid').value.trim();
  const expire_date=document.getElementById('expire_date').value.trim();
  if(!username||!password){alert('Username & Password required'); return;}
  try{
    const res=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,expire_date,hwid})});
    if(res.status===401||res.redirected){alert('Session expired');window.location.href='/login';return;}
    const data=await res.json();
    if(!res.ok||data.error){alert(data.error||('Failed to create user'));return;}
    document.getElementById('username').value='';document.getElementById('password').value='';document.getElementById('hwid').value='';
    fetchUsers();
  }catch(e){alert('Failed to create user');}
}
async function deleteUser(id){if(!confirm('Delete this user?'))return;try{const res=await fetch('/api/users/'+id,{method:'DELETE'});const data=await res.json();if(data.success)fetchUsers();}catch(e){alert('Failed to delete user');}}
async function editUser(id,username,oldPass,oldDate,oldHwid){
  const newPass=prompt('New password for '+username+' (leave blank to keep same):',oldPass);
  const newDate=prompt('New expire date (YYYY-MM-DD, blank to keep same):',oldDate);
  const newHwid=prompt('New HWID (blank to keep same, type "-" to clear):',oldHwid||'');
  if(newPass===null&&newDate===null&&newHwid===null)return;
  const payload={};
  if(newPass!==null&&newPass!==oldPass)payload.password=newPass;
  if(newDate!==null&&newDate!==oldDate)payload.expire_date=newDate;
  if(newHwid!==null){ if(newHwid==='-') payload.hwid=''; else if(newHwid!==oldHwid) payload.hwid=newHwid; }
  if(Object.keys(payload).length===0) return;
  try{ const res=await fetch('/api/users/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json();if(data.error)alert(data.error);else fetchUsers(); }catch(e){alert('Failed to update user');}
}
document.addEventListener('DOMContentLoaded',()=>{fetchServerInfo();fetchUsers();setInterval(fetchUsers,5000);});
</script>

</body>
</html>
HTML_INDEX

# bundle into JSON via python to preserve content exactly
python3 - <<PY
import json,os
p1="/usr/local/zivpn-admin/panel/login.html"
p2="/usr/local/zivpn-admin/panel/index.html"
out="/etc/zivpn-admin/panel.json"
data={}
for p,name in ((p1,"login.html"),(p2,"index.html")):
    try:
        with open(p,"r",encoding="utf-8") as f:
            data[name]=f.read()
    except Exception:
        data[name]=""
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out,"w",encoding="utf-8") as f:
    json.dump(data,f,ensure_ascii=False)
print("WROTE",out)
PY

# secure the JSON and remove original editable files
chown root:root /etc/zivpn-admin/panel.json 2>/dev/null || true
chmod 444 /etc/zivpn-admin/panel.json 2>/dev/null || true
if command -v chattr >/dev/null 2>&1; then
  chattr +i /etc/zivpn-admin/panel.json 2>/dev/null || true
fi

# remove editable panel directory to avoid leaving files behind
rm -rf /usr/local/zivpn-admin/panel 2>/dev/null || true

########################################
# 5. SYSTEMD SERVICE
########################################
cat <<EOF > /etc/systemd/system/zivpn-admin.service
[Unit]
Description=ZIVPN Admin Panel (Web UI)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/zivpn-admin
ExecStart=/usr/local/zivpn-admin/venv/bin/python3 /usr/local/zivpn-admin/server.py
Restart=no

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn-admin.service
systemctl restart zivpn-admin.service || true

SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "========================================"
echo " ZIVPN UDP & Admin Panel Installed"
echo " (Port per User, HWID Note, JSON UI embedded)"
echo "----------------------------------------"
echo " VPS IP        : http://${SERVER_IP}:8989"
echo " UDP Port      : 5667"
echo " Admin USER    : ${ADMIN_USER}"
echo " Admin PASS    : ${ADMIN_PASS}"
echo "----------------------------------------"
echo " Panel JSON    : /etc/zivpn-admin/panel.json (root-only read, immutable if supported)"
echo " Footer Owner  : 🔥 Script Owner By: Jue Htet 🔥"
echo "========================================"

echo
echo "[*] To update the panel UI later:"
echo "    sudo chattr -i /etc/zivpn-admin/panel.json"
echo "    edit /etc/zivpn-admin/panel.json as root (it's JSON with keys 'login.html' and 'index.html')"
echo "    sudo chattr +i /etc/zivpn-admin/panel.json"
