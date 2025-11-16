#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# JVPNSHOP Custom – with Admin Login & Card UI

set -e
export LC_ALL=C

clear
echo "=============================================="
echo "   ZIVPN UDP + Admin Panel Auto Installer"
echo "=============================================="
echo

echo "[0/4] System update & base packages..."
apt-get update -y
apt-get upgrade -y
apt-get install -y sudo curl wget python3 python3-venv python3-pip sqlite3 ufw

# -----------------------------
# 1. INSTALL ZIVPN UDP SERVER
# -----------------------------
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

sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null
sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null

cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
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

if [ -n "\$input_config" ]; then
    IFS=',' read -r -a config <<< "\$input_config"
    if [ \${#config[@]} -eq 1 ]; then
        config+=("\${config[0]}")
    fi
else
    config=("zi")
fi

new_config_str="\"config\": [\$(printf "\"%s\"," "\${config[@]}" | sed 's/,\$//')]"

sed -i -E "s/\"config\": ?\[[[:space:]]*\"zi\"[[:space:]]*\]/\${new_config_str}/g" /etc/zivpn/config.json

systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

# iptables & ufw
DEV=\$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
if [ -n "\$DEV" ]; then
  iptables -t nat -A PREROUTING -i "\$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
fi
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

rm -f zi.* 1>/dev/null 2>/dev/null || true

echo
echo "[+] ZIVPN UDP Installed."

# -----------------------------
# 2. ADMIN LOGIN SETUP
# -----------------------------
echo
echo "[2/4] Configure Admin Panel Login..."

mkdir -p /etc/zivpn-admin

read -p "Set Admin Panel username (default: admin): " ADMIN_USER
if [ -z "\$ADMIN_USER" ]; then
  ADMIN_USER="admin"
fi

read -s -p "Set Admin Panel password (default: admin123): " ADMIN_PASS
echo
if [ -z "\$ADMIN_PASS" ]; then
  ADMIN_PASS="admin123"
fi

# escape double quotes
ADMIN_USER_JSON=\$(printf '%s' "\$ADMIN_USER" | sed 's/\"/\\\\\"/g')
ADMIN_PASS_JSON=\$(printf '%s' "\$ADMIN_PASS" | sed 's/\"/\\\\\"/g')

cat <<EOF > /etc/zivpn-admin/admin.json
{
  "username": "\$ADMIN_USER_JSON",
  "password": "\$ADMIN_PASS_JSON"
}
EOF

# -----------------------------
# 3. ADMIN PANEL BACKEND
# -----------------------------
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
from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, session

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
CONFIG_PATH = "/etc/zivpn/config.json"
ADMIN_FILE = "/etc/zivpn-admin/admin.json"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8989

app = Flask(__name__, static_folder="panel", static_url_path="/panel")
app.secret_key = "zivpn_super_secret_key_change_me"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE,"
        "password TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "expire_at TEXT NOT NULL"
        ")"
    )
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

def sync_config_with_db():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password, expire_at FROM users")
        rows = cur.fetchall()
        conn.close()

        passwords = []
        now = datetime.datetime.utcnow()
        for r in rows:
            expire_at = datetime.datetime.fromisoformat(r["expire_at"])
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

        subprocess.run(["systemctl", "restart", "zivpn.service"], check=False)
    except Exception as e:
        print("sync_config_with_db error:", e)

def user_to_dict(row):
    expire_at = datetime.datetime.fromisoformat(row["expire_at"])
    created_at = datetime.datetime.fromisoformat(row["created_at"])
    now = datetime.datetime.utcnow()
    days_left = (expire_at.date() - now.date()).days
    if days_left < 0:
        days_left = 0
    status = "Online" if expire_at >= now else "Offline"
    return {
        "id": row["id"],
        "username": row["username"],
        "password": row["password"],
        "created_at": created_at.strftime("%Y-%m-%d"),
        "expire_at": expire_at.strftime("%Y-%m-%d"),
        "day_left": days_left,
        "status": status,
    }

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
    return jsonify({
        "ip": ip,
        "panel_port": LISTEN_PORT,
        "udp_port": 5667
    })

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
    online = len([u for u in users if u["status"] == "Online"])
    offline = total - online
    return jsonify({
        "total": total,
        "online": online,
        "offline": offline,
        "users": users
    })

@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    expire_date_str = (data.get("expire_date") or "").strip()

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

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
            "INSERT INTO users (username, password, created_at, expire_at) "
            "VALUES (?, ?, ?, ?)",
            (username, password, created_at, expire_at),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "username already exists"}), 400

    conn.close()
    sync_config_with_db()
    return jsonify({"success": True})

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

if __name__ == "__main__":
    init_db()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

# -----------------------------
# 4. ADMIN PANEL FRONTEND
# -----------------------------
echo
echo "[4/4] Installing Panel UI..."

# login page
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
      width: 28px;
      height: 28px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg,#22c55e,#0ea5e9);
      box-shadow: 0 0 12px rgba(34,197,94,0.7);
      font-weight: 700;
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
    button {
      width: 100%;
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      background: linear-gradient(135deg,#22c55e,#0ea5e9);
      color: #020617;
      font-weight: 600;
      font-size: 0.9rem;
      box-shadow: 0 14px 28px rgba(0,0,0,0.7);
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
    <h1><span class="logo">Z</span>Admin Login</h1>
    <div class="subtitle">Enter the admin username and password from installer output.</div>
    <form method="post">
      <label>Username</label>
      <input name="username" autocomplete="off" required>
      <label>Password</label>
      <input type="password" name="password" autocomplete="off" required>
      <button type="submit">Login</button>
    </form>
    <div class="muted">Protected ZIVPN Admin Panel</div>
  </div>
</body>
</html>
EOF

# main panel UI
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
      background: #020617;
      color: #e5e7eb;
    }
    body {
      margin: 0;
      padding: 0;
      background: radial-gradient(circle at top, #1f2937 0, #020617 45%, #000 100%);
      min-height: 100vh;
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
    }
    h1 {
      font-size: 1.6rem;
      margin: 0 0 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .logo {
      display: inline-flex;
      width: 30px;
      height: 30px;
      border-radius: 999px;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg,#22c55e,#0ea5e9);
      box-shadow: 0 0 18px rgba(34,197,94,0.7);
      font-weight: 700;
      font-size: 18px;
    }
    .subtitle {
      font-size: 0.8rem;
      color: #9ca3af;
      margin-bottom: 14px;
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
      flex: 1 1 auto;
      min-width: 220px;
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
    }
    .stat-label { color:#9ca3af; margin-bottom:2px; display:flex;align-items:center;gap:4px;}
    .stat-value { font-size:1rem;font-weight:600;}
    .pill {
      font-size: 0.7rem;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.5);
      background: rgba(15,23,42,0.95);
    }
    .pill-green {
      border-color: rgba(34,197,94,0.7);
      color: #bbf7d0;
      background: rgba(22,163,74,0.15);
    }
    .pill-red {
      border-color: rgba(248,113,113,0.7);
      color: #fecaca;
      background: rgba(239,68,68,0.15);
    }
    .pill-blue {
      border-color: rgba(59,130,246,0.7);
      color: #bfdbfe;
      background: rgba(37,99,235,0.15);
    }
    .form-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
      align-items: center;
    }
    .input-wrap {
      position: relative;
      flex: 1 1 150px;
      min-width: 150px;
    }
    .input-wrap span.icon {
      position: absolute;
      left: 8px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 0.9rem;
      opacity: 0.8;
    }
    .input-wrap input {
      width: 100%;
      padding: 7px 9px 7px 26px;
      border-radius: 10px;
      border: 1px solid rgba(148,163,184,0.6);
      background: rgba(15,23,42,0.95);
      color: #e5e7eb;
      font-size: 0.85rem;
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
      background: linear-gradient(135deg,#22c55e,#0ea5e9);
      color: #020617;
      font-weight: 600;
      box-shadow: 0 14px 30px rgba(0,0,0,0.7);
      white-space: nowrap;
    }
    .btn-sm {
      padding: 4px 9px;
      font-size: 0.78rem;
      box-shadow: none;
    }
    .btn-ghost {
      background: transparent;
      border: 1px solid rgba(148,163,184,0.6);
      color: #e5e7eb;
    }
    .btn-danger {
      background: rgba(239,68,68,0.12);
      border: 1px solid rgba(248,113,113,0.8);
      color: #fecaca;
    }
    .muted { font-size:0.75rem;color:#9ca3af;margin-bottom:6px;}
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
    .badge-port {font-size:0.7rem;border-radius:999px;padding:2px 7px;border:1px solid rgba(59,130,246,0.8);color:#bfdbfe;background:rgba(37,99,235,0.18);}
    .field-row {display:flex;justify-content:space-between;gap:6px;margin:1px 0;}
    .field-label {color:#9ca3af;}
    .field-value {font-weight:500;}
    .status-dot {width:7px;height:7px;border-radius:999px;display:inline-block;margin-right:4px;}
    .status-online {background:#22c55e;box-shadow:0 0 7px rgba(34,197,94,0.8);}
    .status-offline {background:#6b7280;}
    .actions {display:flex;gap:4px;margin-top:6px;}
    .logout {
      margin-left:auto;
      font-size:0.75rem;
      color:#9ca3af;
    }
    .logout a {color:#f97373;text-decoration:none;}
    @media (max-width:768px){
      .top-row {flex-direction:column;}
      .stat-row {flex-direction:column;}
      .form-row {flex-direction:column;align-items:stretch;}
      .btn {width:100%;justify-content:center;}
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
        <div>
          <h1><span class="logo">Z</span>ZIVPN Admin Panel</h1>
          <div class="subtitle">Control your ZIVPN UDP users with live cards.</div>
        </div>
        <div class="logout">
          ⚙ Admin Panel<br>
          <a href="/logout">Logout</a>
        </div>
      </div>

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
          <div class="stat-label">👥 Total Users</div>
          <div class="stat-value" id="stat-total">0</div>
        </div>
        <div class="stat-chip">
          <div class="stat-label">🟢 Online</div>
          <div class="stat-value" id="stat-online">0</div>
        </div>
        <div class="stat-chip">
          <div class="stat-label">⚪ Offline</div>
          <div class="stat-value" id="stat-offline">0</div>
        </div>
      </div>

      <form id="create-form" onsubmit="createUser(event)">
        <div class="form-row">
          <div class="input-wrap">
            <span class="icon">👤</span>
            <input id="username" name="username" placeholder="Username">
          </div>
          <div class="input-wrap">
            <span class="icon">🔑</span>
            <input id="password" name="password" placeholder="Password">
          </div>
          <div class="input-wrap">
            <span class="icon">📅</span>
            <input id="expire_date" name="expire_date" type="date" placeholder="Expire Date">
          </div>
          <button class="btn" type="submit">
            <span>➕</span> Add Account
          </button>
        </div>
      </form>
      <div class="muted">
        Username / Password / Custom Expire Date ဖြည့်ပြီး <span class="pill pill-green">Add Account</span> နိပ်せနဲ့ Card ထွက်မယ်။
      </div>

      <div id="users-wrap" class="users-grid"></div>
    </div>
  </div>

  <script>
    let serverIpCache = null;
    let udpPortCache = 5667;

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
        udpPortCache = data.udp_port;
        document.getElementById('server-ip').textContent = data.ip;
        document.getElementById('panel-url').textContent = data.ip + ':' + data.panel_port;
        document.getElementById('udp-port-pill').textContent = 'UDP :' + data.udp_port;
      } catch (e) {
        document.getElementById('server-ip').textContent = 'Unknown';
      }
    }

    function renderUsers(data) {
      const wrap = document.getElementById('users-wrap');
      wrap.innerHTML = '';
      document.getElementById('stat-total').textContent = data.total;
      document.getElementById('stat-online').textContent = data.online;
      document.getElementById('stat-offline').textContent = data.offline;

      const vpsIp = serverIpCache || '...';
      data.users.forEach(u => {
        const card = document.createElement('div');
        card.className = 'user-card';
        const statusDotClass = u.status === 'Online' ? 'status-dot status-online' : 'status-dot status-offline';

        card.innerHTML = `
          <div class="user-header">
            <div class="user-title">
              <span>👤</span>
              <span>${u.username}</span>
            </div>
            <span class="badge-port">PORT ${udpPortCache}</span>
          </div>
          <div class="field-row">
            <span class="field-label">VPS IP</span>
            <span class="field-value">${vpsIp}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Password</span>
            <span class="field-value">${u.password}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Day Left</span>
            <span class="field-value">${u.day_left}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Expire Date</span>
            <span class="field-value">${u.expire_at}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Status</span>
            <span class="field-value"><span class="${statusDotClass}"></span>${u.status}</span>
          </div>
          <div class="actions">
            <button class="btn btn-sm btn-ghost" type="button" onclick='editUser(${u.id},"${u.username}","${u.password}","${u.expire_at}")'>✏ Edit</button>
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
        renderUsers(data);
      } catch (e) {
        console.error(e);
      }
    }

    async function createUser(ev) {
      ev.preventDefault();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();
      const expire_date = document.getElementById('expire_date').value.trim();

      if (!username || !password) {
        alert('Username & Password required');
        return;
      }

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, expire_date })
        });
        const data = await res.json();
        if (data.error) {
          alert(data.error);
        } else {
          document.getElementById('username').value = '';
          document.getElementById('password').value = '';
          setDefaultDate();
          fetchUsers();
        }
      } catch (e) {
        alert('Failed to create user');
      }
    }

    async function deleteUser(id) {
      if (!confirm('Delete this user?')) return;
      try {
        const res = await fetch('/api/users/' + id, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          fetchUsers();
        }
      } catch (e) {
        alert('Failed to delete user');
      }
    }

    async function editUser(id, username, oldPass, oldDate) {
      const newPass = prompt('New password for ' + username + ' (leave blank to keep same):', oldPass);
      const newDate = prompt('New expire date (YYYY-MM-DD, blank to keep same):', oldDate);
      if (newPass === null && newDate === null) return;

      const payload = {};
      if (newPass !== null && newPass !== oldPass) payload.password = newPass;
      if (newDate !== null && newDate !== oldDate) payload.expire_date = newDate;

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

    setDefaultDate();
    fetchServerInfo();
    fetchUsers();
    setInterval(fetchUsers, 5000);
  </script>
</body>
</html>
EOF

# -----------------------------
# SYSTEMD SERVICE FOR PANEL
# -----------------------------
cat <<EOF > /etc/systemd/system/zivpn-admin.service
[Unit]
Description=ZIVPN Admin Panel (Web UI)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/zivpn-admin
ExecStart=/usr/local/zivpn-admin/venv/bin/python3 /usr/local/zivpn-admin/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn-admin.service
systemctl start zivpn-admin.service

SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "========================================"
echo " ZIVPN UDP & Admin Panel Installed"
echo "----------------------------------------"
echo " VPS IP        : ${SERVER_IP}"
echo " Admin Panel   : http://${SERVER_IP}:8989"
echo " UDP Port      : 5667"
echo "----------------------------------------"
echo " Admin USER    : ${ADMIN_USER}"
echo " Admin PASS    : ${ADMIN_PASS}"
echo "========================================"
