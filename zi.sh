#!/bin/bash
# Zivpn UDP Module installer
# Creator Zahid Islam

echo -e "Updating server"
sudo apt-get update && apt-get upgrade -y

systemctl stop zivpn.service 1> /dev/null 2> /dev/null

echo -e "Downloading UDP Service"
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn 1> /dev/null 2> /dev/null
chmod +x /usr/local/bin/zivpn

mkdir /etc/zivpn 1> /dev/null 2> /dev/null
wget https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json 1> /dev/null 2> /dev/null

echo "Generating cert files:"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 1> /dev/null 2> /dev/null
sysctl -w net.core.wmem_max=16777216 1> /dev/null 2> /dev/null

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

echo -e "ZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config

if [ -n "$input_config" ]; then
    IFS=',' read -r -a config <<< "$input_config"
    if [ ${#config[@]} -eq 1 ]; then
        config+=(${config[0]})
    fi
else
    config=("zi")
fi

new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"

sed -i -E "s/\"config\": ?\[[[:space:]]*\"zi\"[[:space:]]*\]/${new_config_str}/g" /etc/zivpn/config.json

systemctl enable zivpn.service
systemctl start zivpn.service

iptables -t nat -A PREROUTING -i $(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1) -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 6000:19999/udp
ufw allow 5667/udp

rm zi.* 1> /dev/null 2> /dev/null

echo -e "ZIVPN UDP Installed"

##############################
# ZIVPN ADMIN PANEL INSTALL  #
##############################

echo -e "Installing ZIVPN Admin Panel (Web UI)"

# Install Python and dependencies
apt-get install -y python3 python3-venv python3-pip 1> /dev/null 2> /dev/null

# Create directories
mkdir -p /usr/local/zivpn-admin/panel
mkdir -p /var/lib/zivpn-admin

# Create virtual environment
if [ ! -d "/usr/local/zivpn-admin/venv" ]; then
    python3 -m venv /usr/local/zivpn-admin/venv
fi

/usr/local/zivpn-admin/venv/bin/pip install --upgrade pip 1> /dev/null 2> /dev/null
/usr/local/zivpn-admin/venv/bin/pip install flask 1> /dev/null 2> /dev/null

# Create admin panel backend (server.py)
cat << 'EOF' > /usr/local/zivpn-admin/server.py
#!/usr/bin/env python3
import os
import json
import sqlite3
import datetime
import subprocess
from flask import Flask, request, jsonify, send_from_directory

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
CONFIG_PATH = "/etc/zivpn/config.json"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8989

app = Flask(__name__, static_folder="panel", static_url_path="/panel")

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

def get_server_ip():
    try:
        cmd = "ip -4 route get 1.1.1.1 | awk '{print $7}' | head -1"
        ip = subprocess.check_output(["bash", "-lc", cmd]).decode().strip()
        if not ip:
            raise Exception("empty ip")
        return ip
    except Exception:
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

        try:
            subprocess.run(["systemctl", "restart", "zivpn.service"], check=False)
        except Exception:
            pass
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

@app.route("/")
def index():
    return send_from_directory("panel", "index.html")

@app.route("/api/server", methods=["GET"])
def api_server_info():
    ip = get_server_ip()
    return jsonify({
        "ip": ip,
        "panel_port": LISTEN_PORT
    })

@app.route("/api/users", methods=["GET"])
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
def api_create_user():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    days = data.get("days") or "30"
    try:
        days = int(days)
        if days < 1:
            days = 1
    except ValueError:
        days = 30

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    now = datetime.datetime.utcnow()
    created_at = now.isoformat()
    expire_at = (now + datetime.timedelta(days=days)).isoformat()

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
def api_delete_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    sync_config_with_db()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

# Create admin panel frontend (index.html)
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
      background: #0f172a;
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
      padding: 24px 16px 48px;
    }
    .card {
      background: rgba(15,23,42,0.9);
      border-radius: 16px;
      padding: 20px;
      box-shadow: 0 18px 40px rgba(0,0,0,0.6);
      border: 1px solid rgba(148,163,184,0.2);
      backdrop-filter: blur(12px);
    }
    h1 {
      font-size: 1.6rem;
      margin: 0 0 6px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    h1 span.logo {
      display: inline-flex;
      width: 28px;
      height: 28px;
      border-radius: 999px;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg,#22c55e,#0ea5e9);
      box-shadow: 0 0 20px rgba(34,197,94,0.6);
      font-size: 18px;
    }
    .subtitle {
      font-size: 0.85rem;
      color: #9ca3af;
      margin-bottom: 16px;
    }
    .top-grid {
      display: grid;
      grid-template-columns: minmax(0,1.5fr) minmax(0,1fr);
      gap: 16px;
      margin-bottom: 16px;
      align-items: flex-start;
    }
    .server-info, .stats {
      border-radius: 14px;
      padding: 14px 16px;
      background: rgba(15,23,42,0.9);
      border: 1px solid rgba(148,163,184,0.25);
    }
    .server-info-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: .08em;
      color: #9ca3af;
      margin-bottom: 4px;
    }
    .server-ip {
      font-size: 1.05rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .badge {
      font-size: 0.7rem;
      padding: 3px 7px;
      border-radius: 999px;
      background: rgba(16,185,129,0.15);
      color: #6ee7b7;
      border: 1px solid rgba(16,185,129,0.45);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(3,minmax(0,1fr));
      gap: 10px;
    }
    .stat-chip {
      border-radius: 12px;
      padding: 8px 10px;
      background: rgba(15,23,42,0.95);
      border: 1px solid rgba(148,163,184,0.4);
      font-size: 0.8rem;
    }
    .stat-label {
      color: #9ca3af;
      margin-bottom: 3px;
    }
    .stat-value {
      font-weight: 600;
      font-size: 1rem;
    }
    .form-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 8px;
    }
    .form-row input {
      background: rgba(15,23,42,0.95);
      border-radius: 10px;
      border: 1px solid rgba(148,163,184,0.4);
      color: #e5e7eb;
      padding: 6px 10px;
      font-size: 0.85rem;
      min-width: 0;
      flex: 1;
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
      box-shadow: 0 15px 30px rgba(0,0,0,0.55);
    }
    .btn-sm {
      padding: 4px 9px;
      font-size: 0.8rem;
      box-shadow: none;
    }
    .btn-ghost {
      background: transparent;
      border: 1px solid rgba(148,163,184,0.5);
      color: #e5e7eb;
    }
    .btn-danger {
      background: rgba(248,113,113,0.1);
      border: 1px solid rgba(248,113,113,0.7);
      color: #fecaca;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 0.8rem;
    }
    thead {
      background: rgba(15,23,42,0.95);
    }
    th, td {
      padding: 8px 6px;
      border-bottom: 1px solid rgba(31,41,55,0.8);
      text-align: left;
      white-space: nowrap;
    }
    th {
      font-size: 0.75rem;
      color: #9ca3af;
    }
    tbody tr:hover {
      background: rgba(15,23,42,0.8);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      display: inline-block;
      margin-right: 5px;
    }
    .status-online {
      background: #22c55e;
      box-shadow: 0 0 8px rgba(34,197,94,0.8);
    }
    .status-offline {
      background: #6b7280;
    }
    .muted {
      color: #9ca3af;
      font-size: 0.75rem;
    }
    .tag {
      display: inline-flex;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.6);
      font-size: 0.7rem;
      color: #e5e7eb;
    }
    .actions {
      display: inline-flex;
      gap: 4px;
    }
    .icon {
      font-size: 0.9rem;
    }
    @media (max-width: 768px) {
      .top-grid {
        grid-template-columns: minmax(0,1fr);
      }
      table {
        font-size: 0.75rem;
      }
      th, td {
        padding: 6px 4px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>
        <span class="logo">Z</span>
        ZIVPN Admin Panel
      </h1>
      <div class="subtitle">
        Real-time overview for your ZIVPN UDP Server – users, expiry, and status.
      </div>

      <div class="top-grid">
        <div class="server-info">
          <div class="server-info-label">Server</div>
          <div class="server-ip">
            <span id="server-ip">Detecting...</span>
            <span class="badge">UDP :5667</span>
          </div>
          <div class="muted" style="margin-top:4px;">
            Panel: <span id="panel-url"></span>
          </div>
        </div>
        <div class="stats">
          <div class="stats-grid">
            <div class="stat-chip">
              <div class="stat-label">Total Users</div>
              <div class="stat-value" id="stat-total">0</div>
            </div>
            <div class="stat-chip">
              <div class="stat-label">Online</div>
              <div class="stat-value" id="stat-online">0</div>
            </div>
            <div class="stat-chip">
              <div class="stat-label">Offline</div>
              <div class="stat-value" id="stat-offline">0</div>
            </div>
          </div>
        </div>
      </div>

      <form id="create-form" onsubmit="createUser(event)">
        <div class="form-row">
          <input id="username" name="username" placeholder="Username" required>
          <input id="password" name="password" placeholder="Password" required>
          <input id="days" name="days" type="number" min="1" value="30" placeholder="Days" style="max-width:90px;">
          <button class="btn" type="submit">
            <span class="icon">➕</span>
            Add User
          </button>
        </div>
        <div class="muted">
          For each user: VPS IP, Username, Password, Day Left, Expired Date, Online/Offline can be copied with one click.
        </div>
      </form>

      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>VPS IP</th>
            <th>Username</th>
            <th>Password</th>
            <th>Day Left</th>
            <th>Expired Date</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="users-body">
        </tbody>
      </table>

      <div class="muted" style="margin-top:8px;">
        Auto refresh every 5s. Status = <span class="tag">Online if not expired, Offline if expired</span>
      </div>
    </div>
  </div>

  <script>
    let serverIpCache = null;

    async function fetchServerInfo() {
      try {
        const res = await fetch('/api/server');
        const data = await res.json();
        serverIpCache = data.ip;
        document.getElementById('server-ip').textContent = data.ip;
        document.getElementById('panel-url').textContent = data.ip + ':' + data.panel_port;
      } catch (e) {
        document.getElementById('server-ip').textContent = 'Unknown';
      }
    }

    function renderUsers(data) {
      const tbody = document.getElementById('users-body');
      tbody.innerHTML = '';
      document.getElementById('stat-total').textContent = data.total;
      document.getElementById('stat-online').textContent = data.online;
      document.getElementById('stat-offline').textContent = data.offline;

      data.users.forEach((u, idx) => {
        const tr = document.createElement('tr');
        const serverIp = serverIpCache || '...';
        const statusDotClass = u.status === 'Online' ? 'status-dot status-online' : 'status-dot status-offline';
        tr.innerHTML = `
          <td>${idx + 1}</td>
          <td>${serverIp}</td>
          <td>${u.username}</td>
          <td>${u.password}</td>
          <td>${u.day_left}</td>
          <td>${u.expire_at}</td>
          <td>
            <span class="${statusDotClass}"></span>${u.status}
          </td>
          <td>
            <div class="actions">
              <button class="btn btn-sm btn-ghost" type="button" title="Copy"
                onclick='copyUser("${serverIp}", "${u.username}", "${u.password}", "${u.day_left}", "${u.expire_at}", "${u.status}")'>
                <span class="icon">📋</span>
              </button>
              <button class="btn btn-sm btn-danger" type="button" title="Delete" onclick="deleteUser(${u.id})">
                <span class="icon">🗑️</span>
              </button>
            </div>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function fetchUsers() {
      try {
        const res = await fetch('/api/users');
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
      const days = document.getElementById('days').value.trim() || '30';

      if (!username || !password) return;

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, days })
        });
        const data = await res.json();
        if (data.error) {
          alert(data.error);
        } else {
          document.getElementById('username').value = '';
          document.getElementById('password').value = '';
          document.getElementById('days').value = '30';
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

    function copyUser(vpsIp, username, password, dayLeft, expiredDate, status) {
      const text = `VPS IP: ${vpsIp}
Username: ${username}
Password: ${password}
Day Left: ${dayLeft}
Expired Date: ${expiredDate}
Status: ${status}`;
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

    fetchServerInfo();
    fetchUsers();
    setInterval(fetchUsers, 5000);
  </script>
</body>
</html>
EOF

# Create systemd service for admin panel
cat << EOF > /etc/systemd/system/zivpn-admin.service
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
echo ""
echo "========================================"
echo " ZIVPN UDP & Admin Panel Installed"
echo "----------------------------------------"
echo " VPS IP        : ${SERVER_IP}"
echo " Admin Panel   : http://${SERVER_IP}:8989"
echo " UDP Port      : 5667"
echo "========================================"
