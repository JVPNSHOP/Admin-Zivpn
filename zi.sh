#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# Port per User System
# If You Change Social Link Panel Errors
# Status = Expire Date only (Online/Expiring/Offline)
# Script Owner By: JueHtet (panel custom)
# Updated for both AMD and Intel compatibility

set -e
export LC_ALL=C

# -----------------------------
# Color variables moved up so header can use them
# C1 = light pink-ish, C2= medium pink-ish, C3= deep pink (used for triple color header)
C1="\e[38;2;255;182;193m"
C2="\e[38;2;255;105;180m"
C3="\e[38;2;255;20;147m"
BOLD="\e[1m"
NC="\e[0m"
# PINK used for bottom installed summary (all-pink)
PINK="\e[38;2;255;105;180m"

clear

# Top header now uses three colors (C1,C2,C3)
echo -e "${C1}==============================================${NC}"
echo -e " ${C2}${BOLD}ZIVPN UDP + Admin Panel Auto Installer${NC}"
echo -e " ${C3}( 🔥 Script Owner By : Jue Htet 🔥 )${NC}"
echo -e "${C1}==============================================${NC}"
echo

echo "[0/4] System update & base packages..."
apt-get update -y
# server reset panel
# apt-get upgrade -y
apt-get install -y sudo curl wget python3 python3-venv python3-pip sqlite3 ufw conntrack iproute2 iptables openssl

########################################
# 1. INSTALL ZIVPN UDP SERVER
########################################
echo
echo "[1/4] Installing ZIVPN UDP..."

# Detect system architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        echo "Detected AMD64/x86_64 architecture"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        echo "Detected ARM64 architecture"
        ;;
    i386|i686|x86)
        ARCH="386"
        echo "Detected x86 (32-bit) architecture"
        ;;
    *)
        ARCH="amd64"
        echo "Unknown architecture ($ARCH), defaulting to amd64"
        ;;
esac

systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
mkdir -p /etc/zivpn

echo "Downloading UDP Service..."
wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-${ARCH}" -O /usr/local/bin/zivpn
chmod +x /usr/local/bin/zivpn

echo "Downloading default config..."
wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json

echo "Generating cert files..."
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null || true
sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null || true

cat << EOF > /etc/systemd/system/zivpn.service
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
sed -i -E 's/"config":[[:space:]]/'"$new_config_str"'/g' /etc/zivpn/config.json

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
ufw allow 8989/tcp || true  # Admin panel port allow

# OLD QUOTA CHAIN CLEANUP (if existed)
iptables -t raw -D PREROUTING -p udp --dport 6000:19999 -j ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -F ZIVPN_QUOTA 2>/dev/null || true
iptables -t raw -X ZIVPN_QUOTA 2>/dev/null || true
rm -f zi. 1>/dev/null 2>/dev/null || true

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
echo
read -p "Set Admin Panel password (default: admin123): " ADMIN_PASS
[ -z "$ADMIN_PASS" ] && ADMIN_PASS="admin123"

ADMIN_USER_JSON=$(printf '%s' "$ADMIN_USER" | sed 's/"/\"/g')
ADMIN_PASS_JSON=$(printf '%s' "$ADMIN_PASS" | sed 's/"/\"/g')

cat << EOF > /etc/zivpn-admin/admin.json
{
  "username": "$ADMIN_USER_JSON",
  "password": "$ADMIN_PASS_JSON"
}
EOF

chmod 600 /etc/zivpn-admin/admin.json
chown root:root /etc/zivpn-admin/admin.json

# Create social.json (root-only) so links can't be easily modified by unprivileged users.
# If you want to change them later, edit /etc/zivpn-admin/social.json as root.
mkdir -p /etc/zivpn-admin
cat << 'EOF' > /etc/zivpn-admin/social.json
{
  "telegram": "https://t.me/Pussy1990",
  "facebook": "https://www.facebook.com/juehtet2025",
  "messenger": "https://m.me/juehtet2025",
  "icons": {
    "telegram": "https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/t.png",
    "facebook": "https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/f.png",
    "messenger": "https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/m.png"
  }
}
EOF

chmod 600 /etc/zivpn-admin/social.json
chown root:root /etc/zivpn-admin/social.json

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
from flask import Flask, request, jsonify, send_from_directory, redirect, session, abort

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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expire_at TEXT NOT NULL,
            udp_port INTEGER UNIQUE,
            hwid TEXT
        )
    """)
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
def api_social():
    # Return social links from root-owned social.json (read-only via panel)
    try:
        if not os.path.exists(SOCIAL_FILE):
            return jsonify({"telegram": "", "facebook": "", "messenger": "", "icons": {}})
        with open(SOCIAL_FILE, "r") as f:
            data = json.load(f)
        # return only expected keys (avoid leaking filesystem info)
        result = {
            "telegram": data.get("telegram", ""),
            "facebook": data.get("facebook", ""),
            "messenger": data.get("messenger", ""),
            "icons": data.get("icons", {})
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"telegram": "", "facebook": "", "messenger": "", "icons": {}})

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
        os.chmod(ADMIN_FILE, 0o600)
        return jsonify({"success": True, "username": new_username})
    except Exception as e:
        return jsonify({"error": str(e)}, 500)

if __name__ == "__main__":
    init_db()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

########################################
# 4. FRONTEND (login.html + index.html) - updated to load social links from API
########################################
echo
echo "[4/4] Installing Panel UI..."

# ---- login.html ----
cat << 'EOF' > /usr/local/zivpn-admin/panel/login.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIVPN Admin Login</title>
    <style>
        :root {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
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
        <div style="text-align: center; margin-bottom: 12px;">
            <div class="logo">
                <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/logo.png" alt="ZIVPN Logo">
            </div>
        </div>
        <h1>🔒 Admin Login</h1>
        <div class="subtitle">Enter the admin username and password from installer output.</div>
        
        <form id="login-form" method="POST" action="/login">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" placeholder="admin" required>
            
            <label for="password">Password</label>
            <input type="password" name="password" id="password" placeholder="••••••••" required>
            
            <div class="remember-row">
                <input type="checkbox" id="rememberMe">
                <label for="rememberMe">Save login</label>
            </div>
            
            <button type="submit">Login</button>
        </form>
        
        <div class="muted">
            Protected ZIVPN Admin Panel
        </div>
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
# Note: footer icons removed from static HTML and will be rendered via /api/social
cat << 'EOF' > /usr/local/zivpn-admin/panel/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIVPN Admin Panel</title>
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
        body.light-mode .vps-box {
            background: #eef2ff;
            border-color: #c7d2fe;
        }
        .vps-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: .09em;
            color: #9ca3af;
            margin-bottom: 4px;
        }
        body.light-mode .vps-label {
            color: #6b7280;
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
        body.light-mode .muted {
            color: #6b7280;
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
        body.light-mode .stat-chip {
            background: #e5f0ff;
            border-color: #bfdbfe;
        }
        .stat-label {
            color:#9ca3af; margin-bottom:2px; display:flex;align-items:center;gap:6px;}
        body.light-mode .stat-label {
            color:#6b7280;
        }
        .stat-value {
            font-size:0.9rem;font-weight:600;}
        .stat-dot {
            width:10px; height:10px; border-radius:999px; display:inline-block;
        }
        .stat-dot-online {
            background: radial-gradient(circle at 30% 30%, #bbf7d0 0, #22c55e 40%, #065f46 100%);
            box-shadow:0 0 8px rgba(34,197,94,0.9),0 0 16px rgba(34,197,94,0.6);
            animation:pulseGreen 1.4s ease-in-out infinite;
        }
        .stat-dot-offline {
            background: radial-gradient(circle at 30% 30%, #fecaca 0, #ef4444 40%, #7f1d1d 100%);
            box-shadow:0 0 8px rgba(248,113,113,0.9),0 0 16px rgba(248,113,113,0.6);
            animation:pulseRed 1.4s ease-in-out infinite;
        }
        .pill {
            font-size: 0.7rem;
            padding: 3px 8px;
            border-radius: 999px;
            border: 1px solid rgba(148,163,184,0.5);
            background: rgba(15,23,42,0.95);
        }
        .pill-blue {
            border-color: rgba(34,197,94,0.9);
            color: #bbf7d0;
            background: rgba(22,163,74,0.18);
        }
        body.light-mode .pill-blue {
            background:#bbf7d0;
            border-color:#22c55e;
            color:#166534;
        }
        .form-row {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 10px;
            align-items: stretch;
            width: 100%;
            box-sizing: border-box;
        }
        .input-wrap {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .input-wrap span.icon {
            font-size: 0.8rem;
            opacity: 0.9;
            color: #9ca3af;
        }
        body.light-mode .input-wrap span.icon {
            color: #6b7280;
        }
        .input-wrap input {
            width: 100%;
            padding: 7px 9px;
            border-radius: 10px;
            border: 1px solid rgba(148,163,184,0.6);
            background: rgba(15,23,42,0.95);
            color: #e5e7eb;
            font-size: 0.85rem;
            transition: background 0.25s ease, color 0.25s ease, border-color 0.25s ease;
            box-sizing: border-box;
        }
        body.light-mode .input-wrap input {
            background: #ffffff;
            color: #0f172a;
            border-color: #cbd5f5;
        }
        .btn {
            border-radius: 999px;
            border: none;
            padding: 7px 14px;
            font-size: 0.85rem;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
            background: linear-gradient(135deg,#22c55e,#0ea5e9,#a855f7);
            background-size: 200% 200%;
            color: #020617;
            font-weight: 600;
            box-shadow: 0 14px 30px rgba(0,0,0,0.7);
            white-space: nowrap;
            animation: btnShift 4s ease-in-out infinite;
        }
        @keyframes btnShift{
            0%,100%{background-position:0% 50%;}
            50%{background-position:100% 50%;}
        }
        .btn-sm {
            padding: 4px 9px;
            font-size: 0.78rem;
            box-shadow: none;
        }
        .btn-ghost {
            background: transparent;
            border: 1px solid rgba(148,163,184,0.6);
            color: inherit;
            animation:none; background-size:auto;
        }
        .btn-danger {
            background: rgba(239,68,68,0.12);
            border: 1px solid rgba(248,113,113,0.8);
            color: #fecaca;
            box-shadow:none;
            animation:none;
        }
        body.light-mode .btn-danger {
            background: #fee2e2;
            color: #b91c1c;
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
        body.light-mode .user-card {
            background: #ffffff;
            border-color: #d1d5db;
        }
        .user-header {
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:4px;
        }
        .user-title {
            font-weight:600;
            display:flex;
            align-items:center;
            gap:6px;
            font-size:0.85rem;
        }
        .loader3d {
            width: 12px;
            height: 12px;
            border-radius: 999px;
            background: conic-gradient(#22c55e,#22d3ee,#6366f1,#f97316,#f43f5e,#22c55e);
            animation: spin3d 1s linear infinite;
            box-shadow: 0 0 6px rgba(56,189,248,0.7);
        }
        @keyframes spin3d {
            to { transform: rotate(360deg); }
        }
        .badge-port {
            font-size:0.7rem;
            border-radius:999px;
            padding:2px 7px;
            border:1px solid rgba(34,197,94,0.9);
            color:#bbf7d0;
            background:rgba(22,163,74,0.18);
        }
        body.light-mode .badge-port {
            background:#bbf7d0;
            border-color:#22c55e;
            color:#166534;
        }
        .field-row {
            display:flex;
            justify-content:space-between;
            gap:6px;
            margin:1px 0;
        }
        .field-label {
            color:#9ca3af;
        }
        body.light-mode .field-label {
            color:#6b7280;
        }
        .field-value {
            font-weight:500;
            display:flex;
            align-items:center;
            gap:3px;
            background: linear-gradient(120deg,#22c55e,#0ea5e9,#a855f7);
            background-size:200% 200%;
            -webkit-background-clip:text;
            color: transparent;
            animation:textFlow 5s ease-in-out infinite;
        }
        @keyframes textFlow{
            0%,100%{background-position:0% 50%;}
            50%{background-position:100% 50%;}
        }
        .status-dot {
            width:9px;
            height:9px;
            border-radius:999px;
            display:inline-block;
            margin-right:4px;
        }
        .status-online {
            background: radial-gradient(circle at 30% 30%, #bbf7d0 0, #22c55e 40%, #065f46 100%);
            box-shadow: 0 0 8px rgba(34,197,94,0.9), 0 0 16px rgba(34,197,94,0.6);
            animation:pulseGreen 1.4s ease-in-out infinite;
        }
        .status-warning {
            background: radial-gradient(circle at 30% 30%, #fef9c3 0, #eab308 40%, #854d0e 100%);
            box-shadow:0 0 8px rgba(234,179,8,0.9),0 0 16px rgba(234,179,8,0.6);
            animation:pulseYellow 1.4s ease-in-out infinite;
        }
        .status-offline {
            background: radial-gradient(circle at 30% 30%, #fecaca 0, #ef4444 40%, #7f1d1d 100%);
            box-shadow:0 0 8px rgba(248,113,113,0.9),0 0 16px rgba(248,113,113,0.6);
            animation:pulseRed 1.4s ease-in-out infinite;
        }
        @keyframes pulseGreen {
            0%,100% { transform: scale(1); opacity:1;}
            50% { transform: scale(1.4); opacity:0.6;}
        }
        @keyframes pulseYellow {
            0%,100% { transform: scale(1); opacity:1;}
            50% { transform: scale(1.4); opacity:0.6;}
        }
        @keyframes pulseRed {
            0%,100% { transform: scale(1); opacity:1;}
            50% { transform: scale(1.4); opacity:0.6;}
        }
        .actions {
            display:flex;
            gap:4px;
            margin-top:6px;
        }
        /* ------------------- Floating buttons: Made smaller and equal size (36px) per user request ------------------- */
        .logout-fab {
            position: fixed;
            top: 14px;
            right: 14px;
            width: 36px;
            height: 36px;
            border-radius: 999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg,#f97316,#ef4444);
            color: #0b1120;
            text-decoration: none;
            font-size: 0.95rem;
            box-shadow: 0 14px 30px rgba(0,0,0,0.85);
            border: 1px solid rgba(248,250,252,0.7);
            z-index: 50;
        }
        .theme-fab {
            position: fixed;
            top: 60px;
            right: 14px;
            width: 36px;
            height: 36px;
            border-radius: 999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg,#0ea5e9,#6366f1);
            color: #f9fafb;
            text-decoration: none;
            font-size: 0.95rem;
            box-shadow: 0 12px 28px rgba(0,0,0,0.7);
            border: 1px solid rgba(248,250,252,0.7);
            z-index: 50;
            cursor: pointer;
        }
        .settings-fab {
            position: fixed;
            top: 106px;
            right: 14px;
            width: 36px;
            height: 36px;
            border-radius: 999px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg,#22c55e,#14b8a6);
            color: #0b1120;
            text-decoration: none;
            font-size: 0.95rem;
            box-shadow: 0 12px 28px rgba(0,0,0,0.7);
            border: 1px solid rgba(248,250,252,0.7);
            z-index: 50;
            cursor: pointer;
        }
        .copy-btn {
            border:none;
            background:transparent;
            cursor:pointer;
            font-size:0.78rem;
            padding:0 3px;
            color:inherit;
        }
        /* ---------- FOOTER / SOCIAL ICONS ---------- */
        .footer-icons {
            margin-top: 16px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
            font-size: 0.8rem;
            color: #9ca3af;
        }
        .footer-icons a {
            text-decoration: none;
            width: 36px; /* fixed anchor size so all icons equal */
            height: 36px;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border: none;
            background: rgba(255,255,255,0.03);
        }
        .social-icon {
            width: 22px; /* consistent icon size */
            height: 22px;
            object-fit: contain;
            display: block;
        }
        /* -------------------------------------------- */
        .form-row-extra {
            margin-top: 6px;
        }
        .settings-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(15,23,42,0.75);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 55;
        }
        body.light-mode .settings-backdrop {
            background: rgba(148,163,184,0.6);
        }
        .settings-card {
            background: rgba(15,23,42,0.97);
            border-radius: 16px;
            padding: 14px 16px;
            width: 280px;
            border: 1px solid rgba(148,163,184,0.6);
            box-shadow: 0 18px 40px rgba(0,0,0,0.8);
            font-size: 0.8rem;
        }
        body.light-mode .settings-card {
            background: #ffffff;
            border-color: #d1d5db;
        }
        .settings-card h2 {
            margin: 0 0 8px;
            font-size: 0.95rem;
        }
        .settings-card .desc {
            font-size: 0.75rem;
            color: #9ca3af;
            margin-bottom: 8px;
        }
        body.light-mode .settings-card .desc {
            color: #6b7280;
        }
        .settings-card .field {
            margin-bottom: 6px;
            display: flex;
            flex-direction: column;
            gap: 3px;
        }
        .settings-card label {
            font-size: 0.73rem;
            color: #9ca3af;
        }
        body.light-mode .settings-card label {
            color: #6b7280;
        }
        .settings-card input {
            border-radius: 9px;
            border: 1px solid rgba(148,163,184,0.6);
            padding: 6px 8px;
            font-size: 0.8rem;
            background: rgba(15,23,42,0.95);
            color: #e5e7eb;
        }
        body.light-mode .settings-card input {
            background: #f9fafb;
            color: #0f172a;
            border-color: #cbd5e1;
        }
        .settings-actions {
            margin-top: 8px;
            display: flex;
            justify-content: flex-end;
            gap: 6px;
        }
        @media (max-width:768px){
            .top-row {flex-direction:column;}
            .stat-row {flex-direction:column;}
        }
        #msg-toast {
            position: fixed;
            bottom: 16px;
            left: 50%;
            transform: translateX(-50%);
            min-width: 260px;
            max-width: 360px;
            background: rgba(15,23,42,0.97);
            border-radius: 14px;
            border: 1px solid rgba(148,163,184,0.6);
            padding: 10px 12px;
            font-size: 0.78rem;
            box-shadow: 0 18px 40px rgba(0,0,0,0.8);
            color: #e5e7eb;
            display: none;
            z-index: 60;
        }
        body.light-mode #msg-toast {
            background: #ffffff;
            color: #0f172a;
            border-color: #d1d5db;
        }
        #msg-toast-header {
            display:flex;
            justify-content:space-between;
            align-items:center;
            margin-bottom:4px;
            font-weight:600;
            font-size:0.82rem;
        }
        #msg-toast-rows .row {
            display:flex;
            justify-content:space-between;
            gap:6px;
            margin:1px 0;
        }
        #msg-toast-rows .label {
            color:#9ca3af;
        }
        body.light-mode #msg-toast-rows .label {
            color:#6b7280;
        }
        #msg-toast-rows .value {
            display:flex;
            align-items:center;
            gap:3px;
            font-weight:500;
        }
        #msg-toast-close {
            border:none;
            background:transparent;
            cursor:pointer;
            color:inherit;
            font-size:0.9rem;
        }
    </style>
</head>
<body>
    <!-- Floating Action Buttons -->
    <a href="/logout" class="logout-fab">🔒</a>
    <div id="themeFab" class="theme-fab">🌙</div>
    <div class="settings-fab" onclick="openAdminSettings()">⚙️</div>

    <div class="container">
        <div class="card">
            <!-- Header with Logo -->
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                <div class="logo">
                    <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/logo.png" alt="ZIVPN Logo">
                </div>
                <h1>ZIVPN Admin Panel</h1>
            </div>

            <!-- Server Info -->
            <div class="top-row">
                <div class="vps-box">
                    <div class="vps-label">VPS IP</div>
                    <div class="vps-value">
                        <span id="server-ip">Detecting...</span>
                        <span class="pill pill-blue" id="udp-port-pill">UDP :5667</span>
                    </div>
                    <div class="muted">Admin Panel: <span id="panel-url">...</span></div>
                </div>
            </div>

            <!-- Stats Row -->
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
                <div class="stat-chip">
                    <div class="stat-label">👥 Total Users</div>
                    <div class="stat-value" id="stat-total">0</div>
                </div>
                <div class="stat-chip">
                    <div class="stat-label"><span class="stat-dot stat-dot-online"></span> Online</div>
                    <div class="stat-value" id="stat-online">0</div>
                </div>
                <div class="stat-chip">
                    <div class="stat-label"><span class="stat-dot stat-dot-offline"></span> Offline</div>
                    <div class="stat-value" id="stat-offline">0</div>
                </div>
            </div>

            <!-- Search HWID -->
            <div class="form-row">
                <div class="input-wrap">
                    <span class="icon">🔍</span>
                    <input type="text" id="search-hwid" placeholder="Search by HWID">
                </div>
            </div>

            <!-- Create User Form -->
            <form onsubmit="createUser(event)">
                <div class="form-row">
                    <div class="input-wrap">
                        <span class="icon">👤</span>
                        <input type="text" id="username" placeholder="Username" required>
                    </div>
                    <div class="input-wrap">
                        <span class="icon">🔑</span>
                        <input type="text" id="password" placeholder="Password" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="input-wrap">
                        <span class="icon">🔐</span>
                        <input type="text" id="hwid" placeholder="HWID (optional)">
                    </div>
                    <div class="input-wrap">
                        <span class="icon">📅</span>
                        <input type="date" id="expire_date" required>
                    </div>
                </div>
                <div class="form-row-extra">
                    <button type="submit" class="btn">➕ Add Account</button>
                </div>
            </form>

            <!-- Contact / Social Links -->
            <div style="margin-top: 16px; font-size: 0.8rem; color: #9ca3af;">
                <span>Contact :</span>
                <div class="footer-icons" id="social-links">
                    <!-- Will be filled by JavaScript -->
                </div>
            </div>

            <!-- Users Grid -->
            <div style="margin-top: 16px;">
                <div class="users-grid" id="users-wrap">
                    <!-- User cards will be inserted here -->
                </div>
            </div>
        </div>
    </div>

    <!-- Admin Settings Modal -->
    <div class="settings-backdrop" id="admin-settings-backdrop">
        <div class="settings-card">
            <h2>Admin Settings</h2>
            <div class="desc">Change admin username/password without reinstall.</div>
            <form onsubmit="saveAdminSettings(event)">
                <div class="field">
                    <label>Current Admin Password</label>
                    <input type="password" id="admin-old-pass" required>
                </div>
                <div class="field">
                    <label>New Username (optional)</label>
                    <input type="text" id="admin-new-user">
                </div>
                <div class="field">
                    <label>New Password (optional)</label>
                    <input type="password" id="admin-new-pass">
                </div>
                <div class="settings-actions">
                    <button type="button" class="btn btn-sm btn-ghost" onclick="closeAdminSettings()">Cancel</button>
                    <button type="submit" class="btn btn-sm">Save</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="msg-toast">
        <div id="msg-toast-header">
            <span>Create Account Successfully ✅</span>
            <button id="msg-toast-close" onclick="hideToast()">✕</button>
        </div>
        <div id="msg-toast-rows">
            <!-- rows filled by JS -->
        </div>
    </div>

    <script>
        let serverIpCache = null;
        let lastUsersPayload = null;

        function setDefaultDate() {
            const d = new Date();
            d.setDate(d.getDate() + 30);
            const y = d.getFullYear();
            const m = String(d.getMonth()+1).padStart(2,'0');
            const day = String(d.getDate()).padStart(2,'0');
            document.getElementById('expire_date').value = `${y}-${m}-${day}`;
        }

        async function fetchServerInfo() {
            try {
                const res = await fetch('/api/server');
                const data = await res.json();
                serverIpCache = data.ip;
                document.getElementById('server-ip').textContent = data.ip;
                document.getElementById('panel-url').textContent = data.ip + ':' + data.panel_port;
                document.getElementById('udp-port-pill').textContent = 'UDP :' + data.udp_port;
                
                // CPU / RAM / DISK info ပြ
                const cpu = data.cpu_percent != null ? data.cpu_percent + '%' : '-';
                const ram = (data.mem_used_percent != null && data.mem_total_gb != null) 
                    ? `${data.mem_used_percent}% of ${data.mem_total_gb} GB` : '-';
                const disk = (data.disk_used_percent != null && data.disk_total_gb != null)
                    ? `${data.disk_used_percent}% of ${data.disk_total_gb} GB` : '-';
                
                document.getElementById('stat-cpu').textContent = cpu;
                document.getElementById('stat-ram').textContent = ram;
                document.getElementById('stat-disk').textContent = disk;
            } catch (e) {
                document.getElementById('server-ip').textContent = 'Unknown';
            }
        }

        async function fetchSocialLinks() {
            try {
                const res = await fetch('/api/social');
                if (!res.ok) return;
                const data = await res.json();
                renderSocialLinks(data);
            } catch (e) {
                console.error('fetchSocialLinks error', e);
            }
        }

        function renderSocialLinks(data) {
            const container = document.getElementById('social-links');
            container.innerHTML = '';
            const icons = (data.icons || {});
            const items = [
                { key: 'telegram', url: data.telegram, icon: icons.telegram },
                { key: 'facebook', url: data.facebook, icon: icons.facebook },
                { key: 'messenger', url: data.messenger, icon: icons.messenger }
            ];
            items.forEach(it => {
                if (!it.url) return;
                const a = document.createElement('a');
                a.href = it.url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.title = it.key.charAt(0).toUpperCase() + it.key.slice(1);
                const img = document.createElement('img');
                img.src = it.icon || '';
                img.alt = it.key;
                img.className = 'social-icon';
                a.appendChild(img);
                container.appendChild(a);
            });
        }

        function copyText(text) {
            if (!text) return;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text);
            } else {
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }
        }

        function statusClass(status) {
            if (status === "Online") return "status-online";
            if (status === "Expiring") return "status-warning";
            return "status-offline";
        }

        function renderUsers(data) {
            const wrap = document.getElementById('users-wrap');
            const searchVal = (document.getElementById('search-hwid')?.value || '').trim().toLowerCase();
            const allUsers = data.users || [];
            let users = allUsers;
            if (searchVal) {
                users = allUsers.filter(u => ((u.hwid || '') + '').toLowerCase().includes(searchVal));
            }
            
            wrap.innerHTML = '';
            document.getElementById('stat-total').textContent = data.total;
            document.getElementById('stat-online').textContent = data.online;
            document.getElementById('stat-offline').textContent = data.offline;
            
            const vpsIp = serverIpCache || '...';
            
            users.forEach(u => {
                const card = document.createElement('div');
                card.className = 'user-card';
                const portText = u.udp_port != null ? u.udp_port : '-';
                const safeUser = u.username.replace(/"/g, '&quot;');
                const safePass = u.password.replace(/"/g, '&quot;');
                const safeHwid = (u.hwid || '').replace(/"/g, '&quot;');
                
                card.innerHTML = `
                    <div class="user-header">
                        <div class="user-title">
                            <span class="loader3d"></span>
                            <span>${safeUser}</span>
                        </div>
                        <span class="badge-port">PORT ${portText}</span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">VPS IP</span>
                        <span class="field-value">
                            ${vpsIp}
                            <button class="copy-btn" type="button" onclick="copyText('${vpsIp}')">📋</button>
                        </span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Username</span>
                        <span class="field-value">
                            ${safeUser}
                            <button class="copy-btn" type="button" onclick="copyText('${safeUser}')">📋</button>
                        </span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Password</span>
                        <span class="field-value">
                            ${safePass}
                            <button class="copy-btn" type="button" onclick="copyText('${safePass}')">📋</button>
                        </span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">HWID</span>
                        <span class="field-value">
                            ${safeHwid || '-'}
                            ${safeHwid ? `<button class="copy-btn" type="button" onclick="copyText('${safeHwid}')">📋</button>` : ''}
                        </span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Day Left</span>
                        <span class="field-value">${u.day_left} Days</span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Expire Date</span>
                        <span class="field-value">${u.expire_at}</span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Status</span>
                        <span class="field-value"><span class="status-dot ${statusClass(u.status)}"></span>${u.status}</span>
                    </div>
                    <div class="actions">
                        <button class="btn btn-sm btn-ghost" type="button" onclick='editUser(${u.id},"${safeUser}","${safePass}","${u.expire_at}","${safeHwid}")'>✏ Edit</button>
                        <button class="btn btn-sm btn-danger" type="button" onclick="deleteUser(${u.id})">🗑 Delete</button>
                    </div>
                `;
                wrap.appendChild(card);
            });
        }

        async function fetchUsers() {
            try {
                const res = await fetch('/api/users');
                if (res.status === 401 || res.redirected) {
                    window.location.href = '/login';
                    return;
                }
                const data = await res.json();
                lastUsersPayload = data;
                renderUsers(data);
            } catch (e) {
                console.error(e);
            }
        }

        function showToast(info) {
            const box = document.getElementById('msg-toast');
            const rows = document.getElementById('msg-toast-rows');
            rows.innerHTML = '';
            
            const fields = [
                ['IP', info.ip],
                ['User', info.user],
                ['Pass', info.pass],
                ['HWID', info.hwid],
                ['Day Left', String(info.dayLeft) + ' Days'],
                ['Expire', info.expire],
                ['Port', info.port]
            ];
            
            fields.forEach(([label, value]) => {
                const row = document.createElement('div');
                row.className = 'row';
                row.innerHTML = `
                    <span class="label">${label}</span>
                    <span class="value">
                        ${value}
                        <button class="copy-btn" type="button" onclick="copyText('${value}')">📋</button>
                    </span>
                `;
                rows.appendChild(row);
            });
            
            box.style.display = 'block';
            clearTimeout(box._timer);
            box._timer = setTimeout(hideToast, 8000);
        }

        function hideToast() {
            const box = document.getElementById('msg-toast');
            box.style.display = 'none';
        }

        async function createUser(ev) {
            ev.preventDefault();
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value.trim();
            const hwid = document.getElementById('hwid').value.trim();
            const expire_date = document.getElementById('expire_date').value.trim();
            
            if (!username || !password) {
                alert('Username & Password required');
                return;
            }
            
            try {
                const res = await fetch('/api/users', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, expire_date, hwid })
                });
                
                if (res.status === 401 || res.redirected) {
                    alert('Session expired, please login again.');
                    window.location.href = '/login';
                    return;
                }
                
                const text = await res.text();
                let data = {};
                try {
                    data = text ? JSON.parse(text) : {};
                } catch (e) {
                    console.error('JSON parse error:', e, text);
                    alert('Failed to create user (invalid server response).');
                    return;
                }
                
                if (!res.ok || data.error) {
                    alert(data.error || ('Failed to create user (HTTP ' + res.status + ')'));
                    return;
                }
                
                const today = new Date();
                const exp = new Date(expire_date || document.getElementById('expire_date').value);
                const diffMs = exp - today;
                let dayLeft = Math.ceil(diffMs / (1000*60*60*24));
                if (dayLeft < 0) dayLeft = 0;
                
                showToast({
                    ip: serverIpCache || '...',
                    user: username,
                    pass: password,
                    hwid: hwid || '-',
                    dayLeft: dayLeft,
                    expire: expire_date || document.getElementById('expire_date').value,
                    port: data.udp_port ? data.udp_port : 'Auto-Assign'
                });
                
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
                document.getElementById('hwid').value = '';
                setDefaultDate();
                fetchUsers();
                
            } catch (e) {
                console.error(e);
                alert('Failed to create user: ' + (e.message || e));
            }
        }

        async function deleteUser(id) {
            if (!confirm('Delete this user?')) return;
            try {
                const res = await fetch('/api/users/' + id, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) fetchUsers();
            } catch (e) {
                alert('Failed to delete user');
            }
        }

        async function editUser(id, username, oldPass, oldDate, oldHwid) {
            const newPass = prompt('New password for ' + username + ' (leave blank to keep same):', oldPass);
            const newDate = prompt('New expire date (YYYY-MM-DD, blank to keep same):', oldDate);
            const newHwid = prompt('New HWID (blank to keep same, type "-" to clear):', oldHwid || '');
            
            if (newPass === null && newDate === null && newHwid === null) return;
            
            const payload = {};
            if (newPass !== null && newPass !== oldPass) payload.password = newPass;
            if (newDate !== null && newDate !== oldDate) payload.expire_date = newDate;
            if (newHwid !== null) {
                if (newHwid === "-") {
                    payload.hwid = "";
                } else if (newHwid !== oldHwid) {
                    payload.hwid = newHwid;
                }
            }
            
            if (Object.keys(payload).length === 0) return;
            
            try {
                const res = await fetch('/api/users/' + id, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.error) alert(data.error);
                else fetchUsers();
            } catch (e) {
                alert('Failed to update user');
            }
        }

        function applyThemeFromStorage() {
            const mode = localStorage.getItem('zivpn_theme') || 'dark';
            const body = document.body;
            const fab = document.getElementById('themeFab');
            if (mode === 'light') {
                body.classList.add('light-mode');
                fab.textContent = '☀';
            } else {
                body.classList.remove('light-mode');
                fab.textContent = '🌙';
            }
        }

        function toggleTheme() {
            const body = document.body;
            if (body.classList.contains('light-mode')) {
                localStorage.setItem('zivpn_theme', 'dark');
            } else {
                localStorage.setItem('zivpn_theme', 'light');
            }
            applyThemeFromStorage();
        }

        function openAdminSettings() {
            document.getElementById('admin-settings-backdrop').style.display = 'flex';
            document.getElementById('admin-old-pass').value = '';
            document.getElementById('admin-new-user').value = '';
            document.getElementById('admin-new-pass').value = '';
        }

        function closeAdminSettings() {
            document.getElementById('admin-settings-backdrop').style.display = 'none';
        }

        async function saveAdminSettings(ev) {
            ev.preventDefault();
            const oldPass = document.getElementById('admin-old-pass').value.trim();
            const newUser = document.getElementById('admin-new-user').value.trim();
            const newPass = document.getElementById('admin-new-pass').value.trim();
            
            if (!oldPass) {
                alert('Please enter current password');
                return;
            }
            
            try {
                const res = await fetch('/api/admin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ old_password: oldPass, new_username: newUser, new_password: newPass })
                });
                const data = await res.json();
                if (data.error) {
                    alert(data.error);
                } else {
                    alert('Admin credentials updated successfully');
                    closeAdminSettings();
                }
            } catch (e) {
                alert('Failed to update admin settings');
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            const hwidInput = document.getElementById('search-hwid');
            if (hwidInput) {
                hwidInput.addEventListener('input', () => {
                    if (lastUsersPayload) {
                        renderUsers(lastUsersPayload);
                    }
                });
            }
        });

        // Initialize
        setDefaultDate();
        applyThemeFromStorage();
        fetchServerInfo();
        fetchSocialLinks();
        fetchUsers();
        setInterval(fetchUsers, 5000);
        
        // Attach theme toggle
        document.getElementById('themeFab').addEventListener('click', toggleTheme);
    </script>
</body>
</html>
EOF

########################################
# SYSTEMD SERVICE FOR PANEL
########################################
cat << EOF > /etc/systemd/system/zivpn-admin.service
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

# Bottom summary: make all-pink (PINK variable)
echo
echo -e "${PINK}========================================${NC}"
echo -e "  ${PINK}${BOLD}ZIVPN UDP & Admin Panel Installed${NC}"
echo -e "  ${PINK}(ကျေးဇူးပြုပြီးကျနော့် Script ကိုမခိုးပါနဲ့)${NC}"
echo -e "${PINK}----------------------------------------${NC}"
echo -e "  ${PINK}VPS IP :${NC} ${SERVER_IP}"
echo -e "  ${PINK}Admin Panel :${NC} http://${SERVER_IP}:8989"
echo -e "  ${PINK}UDP Port :${NC} 5667"
echo -e "${PINK}----------------------------------------${NC}"
echo -e "  ${PINK}Admin USER :${NC} ${ADMIN_USER}"
echo -e "  ${PINK}Admin PASS :${NC} ${ADMIN_PASS}"
echo -e "  ${PINK}Script Owner By:${NC} JueHtet"
echo -e "${PINK}========================================${NC}"
