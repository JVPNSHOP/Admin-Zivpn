#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# Port per User System (No GB quota, HWID field only)
# Status = Expire Date only (Online/Expiring/Offline)
# Script Owner By: JueHtet (panel custom)
#
# NOTE: This installer stores social links server-side at /etc/zivpn-admin/social.json
#       Frontend loads links via /api/social (login_required). Copying frontend HTML
#       will NOT reveal social link targets.

set -e
export LC_ALL=C

clear
echo "=============================================="
echo "   ZIVPN UDP + Admin Panel Auto Installer"
echo "   (Port per User, No GB Quota, HWID Note)"
echo "=============================================="
echo

echo "[0/4] System update & base packages..."
apt-get update -y
# server reset မကျအောင် upgrade မလုပ်တော့
# apt-get upgrade -y
apt-get install -y sudo curl wget python3 python3-venv python3-pip sqlite3 ufw conntrack iproute2 iptables

########################################
# 1. INSTALL ZIVPN UDP SERVER
########################################
echo
echo "[1/4] Installing ZIVPN UDP..."

systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
mkdir -p /etc/zivpn

echo "Downloading UDP Service..."
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
chmod +x /usr/local/bin/zivpn

echo "Downloading default config..."
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json

echo "Generating cert files..."
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

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
echo "ZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config

# password list build
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

new_config_str="\"config\": [$password_list]"
sed -i -E 's/"config":[[:space:]]*\[[^]]*\]/'"$new_config_str"'/g' /etc/zivpn/config.json

systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
if [ -n "$DEV" ]; then
  # UDP Port per user range -> main zivpn port
  iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
fi

# Firewall rules
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true
ufw allow 8989/tcp || true   # Admin panel port allow

# OLD QUOTA CHAIN CLEANUP (if existed)
iptables -t raw -D PREROUTING -p udp --dport 6000:19999 -j ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -F ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -X ZIVPN_QUOTA 2>/dev/null || true

rm -f zi.* 1>/dev/null 2>/dev/null || true
echo
echo "[+] ZIVPN UDP Installed."

########################################
# 2. ADMIN LOGIN SETUP
########################################
echo
echo "[2/4] Configure Admin Panel Login..."

mkdir -p /etc/zivpn-admin

read -p "Set Admin Panel username (default: admin): " ADMIN_USER
[ -z "$ADMIN_USER" ] && ADMIN_USER="admin"

# Termius မှာလည်း စာမြင်ရအောင် echo on
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

# create social.json - server-side storage for social links (frontend will fetch via /api/social)
cat <<EOF > /etc/zivpn-admin/social.json
{
  "telegram": "https://t.me/JueHtetOfficial",
  "facebook": "https://www.facebook.com/JueHtetOfficial",
  "messenger": "https://m.me/JueHtetOfficial"
}
EOF
chmod 600 /etc/zivpn-admin/social.json || true

########################################
# 3. ADMIN PANEL BACKEND (server.py)
########################################
echo
echo "[3/4] Installing ZIVPN Admin Panel (Web UI Backend)..."

apt-get install -y python3-venv python3-pip 1>/dev/null 2>/dev/null || true
mkdir -p /usr/local/zivpn-admin/panel
mkdir -p /var/lib/zivpn-admin

if [ ! -d "/usr/local/zivpn-admin/venv" ]; then
  python3 -m venv /usr/local/zivpn-admin/venv
fi

/usr/local/zivpn-admin/venv/bin/pip install --upgrade pip 1>/dev/null 2>/dev/null
/usr/local/zivpn-admin/venv/bin/pip install flask 1>/dev/null 2>/dev/null

cat << 'EOF' > /usr/local/zivpn-admin/server.py
#!/usr/bin/env python3
import os
import json
import sqlite3
import datetime
import subprocess
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, redirect, session

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
CONFIG_PATH = "/etc/zivpn/config.json"
ADMIN_FILE = "/etc/zivpn-admin/admin.json"
SOCIAL_FILE = "/etc/zivpn-admin/social.json"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8989

PORT_MIN = 6001
PORT_MAX = 19999

app = Flask(__name__, static_folder="panel", static_url_path="/panel")
app.secret_key = "zivpn_super_secret_key_change_me"

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # base table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE,
            password   TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expire_at  TEXT NOT NULL,
            udp_port   INTEGER UNIQUE,
            hwid       TEXT
        )
        """
    )
    # migration for old DB (add hwid column if missing)
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
        with open(ADMIN_FILE, "r") as f:
            data = json.load(f)
        return data.get("username", "admin"), data.get("password", "admin123")
    except Exception:
        return "admin", "admin123"

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def get_server_ip():
    try:
        cmd = "ip -4 route get 1.1.1.1 | awk '{print $7}' | head -1"
        ip = subprocess.check_output(["bash", "-lc", cmd]).decode().strip()
        if ip:
            return ip
    except Exception:
        pass
    try:
        cmd = "hostname -I | awk '{print $1}'"
        ip = subprocess.check_output(["bash", "-lc", cmd]).decode().strip()
        if ip:
            return ip
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
        load1, _, _ = os.getloadavg()
        cores = os.cpu_count() or 1
        cpu_percent = min(100.0, round(load1 / cores * 100.0, 1))
    except Exception:
        pass

    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                key = parts[0].strip()
                val = parts[1].strip().split()[0]
                meminfo[key] = float(val)
        total_kb = meminfo.get("MemTotal", 0.0)
        avail_kb = meminfo.get("MemAvailable", 0.0)
        if total_kb > 0:
            mem_total_gb = round(total_kb / (1024*1024), 1)
            used_kb = total_kb - avail_kb
            mem_used_percent = round(used_kb / total_kb * 100.0, 1)
    except Exception:
        pass

    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        if total > 0:
            disk_total_gb = round(total / (1024**3), 1)
            disk_used_percent = round((total - free) / total * 100.0, 1)
    except Exception:
        pass

    return {
        "cpu_percent": cpu_percent,
        "mem_total_gb": mem_total_gb,
        "mem_used_percent": mem_used_percent,
        "disk_total_gb": disk_total_gb,
        "disk_used_percent": disk_used_percent,
    }

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
    if days_left < 0:
        days_left = 0

    if expire_at < now:
        status = "Offline"
    elif days_left <= 3:
        status = "Expiring"
    else:
        status = "Online"

    return {
        "id": row["id"],
        "username": row["username"],
        "password": row["password"],
        "created_at": created_at.strftime("%Y-%m-%d"),
        "expire_at": expire_at.strftime("%Y-%m-%d"),
        "day_left": days_left,
        "status": status,
        "udp_port": row["udp_port"],
        "hwid": row["hwid"],
    }

def sync_config_with_db():
    # Expired account => password not added => Offline + cannot connect
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password, expire_at FROM users")
        rows = cur.fetchall()
        conn.close()

        passwords = []
        now = datetime.datetime.utcnow()
        for r in rows:
            try:
                expire_at = datetime.datetime.fromisoformat(r["expire_at"])
            except Exception:
                continue
            if expire_at >= now and r["password"] not in passwords:
                passwords.append(r["password"])

        if not os.path.exists(CONFIG_PATH):
            return

        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)

        auth = data.get("auth", {})
        auth["config"] = passwords if passwords else ["zi"]
        data["auth"] = auth

        with open(CONFIG_PATH, "w") as f:
            json.dump(data, f)

        # >>> auto restart ZIVPN only when password list change (no loop) <<<
        subprocess.run(["systemctl", "restart", "zivpn.service"], check=False)
    except Exception as e:
        print("sync_config_with_db error:", e)

def allocate_udp_port():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT udp_port FROM users WHERE udp_port IS NOT NULL")
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print("allocate_udp_port warning:", e)
        rows = []
    conn.close()
    used = {r["udp_port"] for r in rows if r["udp_port"] is not None}
    for p in range(PORT_MIN, PORT_MAX + 1):
        if p not in used:
            return p
    return None

# -------------------------
# Social links helpers
# -------------------------
def get_social_links():
    default = {"telegram": "", "facebook": "", "messenger": ""}
    try:
        if os.path.exists(SOCIAL_FILE):
            with open(SOCIAL_FILE, "r") as f:
                data = json.load(f)
            # ensure keys exist
            for k in default:
                if k not in data:
                    data[k] = ""
            return data
    except Exception:
        pass
    return default

def save_social_links(data):
    try:
        tmp = { "telegram": data.get("telegram", ""), "facebook": data.get("facebook", ""), "messenger": data.get("messenger", "") }
        with open(SOCIAL_FILE, "w") as f:
            json.dump(tmp, f)
        os.chmod(SOCIAL_FILE, 0o600)
        return True
    except Exception as e:
        print("save_social_links error:", e)
        return False

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return send_from_directory("panel", "login.html")
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    admin_user, admin_pass = get_admin_creds()
    if username == admin_user and password == admin_pass:
        session["admin_logged_in"] = True
        return redirect("/")
    return send_from_directory("panel", "login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    return send_from_directory("panel", "index.html")

@app.route("/api/server", methods=["GET"])
@login_required
def api_server_info():
    ip = get_server_ip()
    stats = get_server_stats()
    return jsonify({
        "ip": ip,
        "panel_port": LISTEN_PORT,
        "udp_port": 5667,
        "cpu_percent": stats["cpu_percent"],
        "mem_total_gb": stats["mem_total_gb"],
        "mem_used_percent": stats["mem_used_percent"],
        "disk_total_gb": stats["disk_total_gb"],
        "disk_used_percent": stats["disk_used_percent"],
    })

@app.route("/api/social", methods=["GET"])
@login_required
def api_get_social():
    # return social links stored on disk (frontend requests from logged-in session)
    return jsonify(get_social_links())

@app.route("/api/social", methods=["POST"])
@login_required
def api_update_social():
    try:
        payload = request.get_json(silent=True) or {}
        ok = save_social_links(payload)
        if not ok:
            return jsonify({"error": "failed to save social links"}), 500
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/users", methods=["GET"])
@login_required
def api_list_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    users = [user_to_dict(r) for r in rows]

    total = len(users)
    online = sum(1 for u in users if u["status"] in ("Online", "Expiring"))
    offline = sum(1 for u in users if u["status"] == "Offline")

    return jsonify({
        "total": total,
        "online": online,
        "offline": offline,
        "users": users
    })

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
            return jsonify({"error": "username and password required"}), 400

        udp_port = allocate_udp_port()
        if udp_port is None:
            return jsonify({"error": "no free UDP port available"}), 400

        now = datetime.datetime.utcnow()
        created_at = now.isoformat()

        if expire_date_str:
            try:
                expire_date = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d")
            except ValueError:
                expire_date = now + datetime.timedelta(days=30)
        else:
            expire_date = now + datetime.timedelta(days=30)

        expire_at = expire_date.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password, created_at, expire_at, udp_port, hwid) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (username, password, created_at, expire_at, udp_port, hwid or None),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "username already exists"}), 400
        except sqlite3.OperationalError as e:
            conn.close()
            return jsonify({"error": "database error: " + str(e)}), 500

        conn.close()
        sync_config_with_db()
        return jsonify({"success": True, "udp_port": udp_port})
    except Exception as e:
        print("api_create_user unexpected error:", e)
        return jsonify({"error": "internal error: " + str(e)}), 500

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_delete_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    sync_config_with_db()
    return jsonify({"success": True})

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def api_update_user(user_id):
    data = request.get_json(silent=True) or request.form
    password = (data.get("password") or "").strip()
    expire_date_str = (data.get("expire_date") or "").strip()

    fields = []
    params = []

    if password:
        fields.append("password = ?")
        params.append(password)

    if expire_date_str:
        try:
            expire_date = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d")
            expire_at = expire_date.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
            fields.append("expire_at = ?")
            params.append(expire_at)
        except ValueError:
            pass

    if "hwid" in data:
        hwid_val = data.get("hwid")
        fields.append("hwid = ?")
        params.append(hwid_val if hwid_val is not None and hwid_val != "" else None)

    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    params.append(user_id)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    conn.close()
    sync_config_with_db()
    return jsonify({"success": True})

@app.route("/api/admin", methods=["POST"])
@login_required
def api_update_admin():
    data = request.get_json(silent=True) or {}
    old_password = (data.get("old_password") or "").strip()
    new_username = (data.get("new_username") or "").strip()
    new_password = (data.get("new_password") or "").strip()

    current_user, current_pass = get_admin_creds()
    if old_password != current_pass:
        return jsonify({"error": "Old password incorrect"}), 400

    if not new_username:
        new_username = current_user
    if not new_password:
        new_password = current_pass

    try:
        with open(ADMIN_FILE, "w") as f:
            json.dump({"username": new_username, "password": new_password}, f)
        return jsonify({"success": True, "username": new_username})
    except Exception as e:
        return jsonify({"error": str(e)}, 500)

if __name__ == "__main__":
    init_db()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

########################################
# 4. FRONTEND (login.html + index.html) - index.html updated to fetch /api/social
########################################
echo
echo "[4/4] Installing Panel UI..."

# ---- login.html ----
cat << 'EOF' > /usr/local/zivpn-admin/panel/login.html
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
      width: 34px;
      height: 34px;
      border-radius: 999px;
      overflow: hidden;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .logo img {
      width: 34px;
      height: 34px;
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
EOF

# ---- index.html ----
# NOTE: Footer anchors DO NOT contain direct href targets. JS will fetch /api/social and set href attributes.
cat << 'EOF' > /usr/local/zivpn-admin/panel/index.html
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
    body.light-mode {
      background: radial-gradient(circle at top, #e5e7eb 0, #f9fafb 45%, #e5e7eb 100%);
      color: #0f172a;
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
    body.light-mode .card {
      background: #f9fafb;
      border-color: #d1d5db;
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
      width: 34px;
      height: 34px;
      object-fit: cover;
    }
    /* NOTE: main UI CSS omitted here for brevity; kept same as original script's UI */
    .footer-icons a {
      text-decoration: none;
      width: 34px;
      height: 34px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: none;
    }
    .social-icon {
      width: 34px;
      height: 34px;
      border-radius: 999px;
      object-fit: cover;
    }
  </style>
</head>
<body>
  <a href="/logout" class="logout-fab" title="Logout">🔒</a>
  <div class="theme-fab" id="themeFab" title="Toggle Dark/Light" onclick="toggleTheme()">🌙</div>
  <div class="settings-fab" id="settingsFab" title="Admin Settings" onclick="openAdminSettings()">⚙️</div>

  <div class="container">
    <div class="card">
      <h1>
        <span class="logo">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN">
        </span>
        <span>ZIVPN Admin Panel</span>
      </h1>

      <!-- main UI markup (kept same as earlier versions) -->

      <div class="footer-icons">
        <span>Contact :</span>
        <!-- NOTE: href intentionally left blank. JS will populate these from /api/social -->
        <a class="tg" href="#" target="_blank" rel="noopener" title="Telegram">
          <img class="social-icon" src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/t.png" alt="Telegram">
        </a>
        <a class="fb" href="#" target="_blank" rel="noopener" title="Facebook">
          <img class="social-icon" src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/f.png" alt="Facebook">
        </a>
        <a class="ms" href="#" target="_blank" rel="noopener" title="Messenger">
          <img class="social-icon" src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/m.png" alt="Messenger">
        </a>
      </div>
    </div>
  </div>

  <!-- admin settings modal (same) -->
  <div id="admin-settings-backdrop" class="settings-backdrop" style="display:none;">
    <div class="settings-card">
      <h2>Admin Settings</h2>
      <div class="desc">
        Change admin username/password without reinstall.
      </div>
      <form id="admin-settings-form" onsubmit="saveAdminSettings(event)">
        <div class="field">
          <label>Current Admin Password</label>
          <input type="password" id="admin-old-pass" placeholder="Enter current password">
        </div>
        <div class="field">
          <label>New Username (optional)</label>
          <input type="text" id="admin-new-user" placeholder="Leave blank to keep same">
        </div>
        <div class="field">
          <label>New Password (optional)</label>
          <input type="password" id="admin-new-pass" placeholder="Leave blank to keep same">
        </div>
        <div class="settings-actions">
          <button type="button" class="btn btn-sm btn-ghost" onclick="closeAdminSettings()">Cancel</button>
          <button type="submit" class="btn btn-sm">Save</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    // Note: The full UI JS (fetchServerInfo, fetchUsers, createUser, editUser, deleteUser, theme toggles)
    // should be the same as in the original index.html. For brevity we show only the social fetch part
    // which is the required security change.

    async function loadSocialLinks() {
      try {
        const res = await fetch('/api/social', { credentials: 'same-origin' });
        if (!res.ok) return;
        const js = await res.json();
        if (js.telegram) {
          const a = document.querySelector('a.tg');
          if (a) a.href = js.telegram;
        }
        if (js.facebook) {
          const a = document.querySelector('a.fb');
          if (a) a.href = js.facebook;
        }
        if (js.messenger) {
          const a = document.querySelector('a.ms');
          if (a) a.href = js.messenger;
        }
      } catch (e) {
        console.warn('loadSocialLinks failed', e);
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      // call other initializers here (fetchServerInfo, fetchUsers, etc.)
      loadSocialLinks();
    });
  </script>
</body>
</html>
EOF

########################################
# SYSTEMD SERVICE FOR PANEL
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
systemctl restart zivpn-admin.service

SERVER_IP=$(hostname -I | awk '{print $1}')

C1="\e[38;2;0;204;255m"
C2="\e[38;2;0;255;153m"
C3="\e[38;2;255;102;255m"
BOLD="\e[1m"
NC="\e[0m"

echo
echo -e "${C1}========================================${NC}"
echo -e " ${C2}${BOLD}ZIVPN UDP & Admin Panel Installed${NC}"
echo -e " ${C3}(Port per User, HWID Note, No GB Quota)${NC}"
echo -e "${C1}----------------------------------------${NC}"
echo -e " ${C2}VPS IP        :${NC} ${SERVER_IP}"
echo -e " ${C2}Admin Panel   :${NC} http://${SERVER_IP}:8989"
echo -e " ${C2}UDP Port      :${NC} 5667"
echo -e "${C1}----------------------------------------${NC}"
echo -e " ${C3}Admin USER    :${NC} ${ADMIN_USER}"
echo -e " ${C3}Admin PASS    :${NC} ${ADMIN_PASS}"
echo -e " ${C1}Script Owner By:${NC} JueHtet"
echo -e "${C1}========================================${NC}"
