#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# Port-per-User + Flow Quota Version
# Script Owner By: JueHtet

set -e
export LC_ALL=C

clear
echo "=============================================="
echo "   ZIVPN UDP + Admin Panel Auto Installer"
echo "   (Port per User + Flow Quota)"
echo "   Script Owner By: JueHtet"
echo "=============================================="
echo

echo "[0/4] System update & base packages..."
apt-get update -y
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

cat <<EOF >/etc/systemd/system/zivpn.service
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

if [ -z "$input_config" ]; then
  password_list="\"zi\""
else
  OLD_IFS="$IFS"
  IFS=','
  set -- $input_config
  password_list=""
  for p in "$@"; do
    p_trim=$(echo "$p" | xargs)
    [ -z "$p_trim" ] && continue
    password_list="${password_list}\"$p_trim\","
  done
  IFS="$OLD_IFS"
  password_list=${password_list%,}
  [ -z "$password_list" ] && password_list="\"zi\""
fi

new_config_str="\"config\": [$password_list]"
sed -i -E 's/"config":[[:space:]]*\[[^]]*\]/'"$new_config_str"'/g' /etc/zivpn/config.json

systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
if [ -n "$DEV" ]; then
  iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
fi
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

# quota chain for per-port flow counting
iptables -N ZIVPN_QUOTA 2>/dev/null || true
iptables -C INPUT -p udp --dport 6000:19999 -j ZIVPN_QUOTA 2>/dev/null || iptables -A INPUT -p udp --dport 6000:19999 -j ZIVPN_QUOTA

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

read -p "Set Admin Panel password (default: admin123): " ADMIN_PASS
[ -z "$ADMIN_PASS" ] && ADMIN_PASS="admin123"

ADMIN_USER_JSON=$(printf '%s' "$ADMIN_USER" | sed 's/\"/\\\"/g')
ADMIN_PASS_JSON=$(printf '%s' "$ADMIN_PASS" | sed 's/\"/\\\"/g')

cat <<EOF >/etc/zivpn-admin/admin.json
{
  "username": "$ADMIN_USER_JSON",
  "password": "$ADMIN_PASS_JSON"
}
EOF

########################################
# 3. ADMIN PANEL BACKEND (server.py)
########################################
echo
echo "[3/4] Installing ZIVPN Admin Panel (Web UI Backend)..."

mkdir -p /usr/local/zivpn-admin/panel
mkdir -p /var/lib/zivpn-admin

if [ ! -d "/usr/local/zivpn-admin/venv" ]; then
  python3 -m venv /usr/local/zivpn-admin/venv
fi

/usr/local/zivpn-admin/venv/bin/pip install --upgrade pip >/dev/null 2>&1 || true
/usr/local/zivpn-admin/venv/bin/pip install flask >/dev/null 2>&1

cat << 'EOF' >/usr/local/zivpn-admin/server.py
#!/usr/bin/env python3
import os
import json
import sqlite3
import datetime
import subprocess
import threading
import time
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, redirect, session

DB_PATH = "/var/lib/zivpn-admin/zivpn.db"
CONFIG_PATH = "/etc/zivpn/config.json"
ADMIN_FILE = "/etc/zivpn-admin/admin.json"
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8989

PORT_MIN = 6001
PORT_MAX = 19999
QUOTA_CHAIN = "ZIVPN_QUOTA"

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
    cur.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if "quota_gb" not in cols:
        try:
            cur.execute("ALTER TABLE users ADD COLUMN quota_gb REAL")
        except Exception:
            pass
    if "udp_port" not in cols:
        try:
            cur.execute("ALTER TABLE users ADD COLUMN udp_port INTEGER UNIQUE")
        except Exception:
            pass
    if "used_bytes" not in cols:
        try:
            cur.execute("ALTER TABLE users ADD COLUMN used_bytes INTEGER DEFAULT 0")
        except Exception:
            pass
    conn.commit()
    conn.close()

def ensure_db_ready():
    try:
        init_db()
    except Exception as e:
        print("init_db error:", e)

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
    try:
        load1, _, _ = os.getloadavg()
        cores = os.cpu_count() or 1
        cpu_percent = min(100.0, round(load1 / cores * 100.0, 1))
    except Exception:
        cpu_percent = None

    mem_total_gb = None
    mem_used_percent = None
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

    disk_total_gb = None
    disk_used_percent = None
    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        if total > 0:
            disk_total_gb = round(total / (1024**3), 1)
            used = total - free
            disk_used_percent = round(used / total * 100.0, 1)
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
    expire_at = datetime.datetime.fromisoformat(row["expire_at"])
    created_at = datetime.datetime.fromisoformat(row["created_at"])
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

    quota = row["quota_gb"]
    used_bytes = row["used_bytes"] if row["used_bytes"] is not None else 0
    used_gb = round(used_bytes / (1024**3), 3) if used_bytes else 0.0
    left_gb = None
    if quota is not None:
        left_val = quota - used_gb
        if left_val < 0:
            left_val = 0.0
        left_gb = round(left_val, 3)

    return {
        "id": row["id"],
        "username": row["username"],
        "password": row["password"],
        "created_at": created_at.strftime("%Y-%m-%d"),
        "expire_at": expire_at.strftime("%Y-%m-%d"),
        "day_left": days_left,
        "status": status,
        "quota_gb": quota,
        "udp_port": row["udp_port"],
        "used_gb": used_gb,
        "left_gb": left_gb,
    }

def sync_config_with_db():
    try:
        ensure_db_ready()
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

def ensure_quota_chain():
    try:
        subprocess.run(
            ["bash", "-lc",
             f"iptables -N {QUOTA_CHAIN} 2>/dev/null || true; "
             f"iptables -C INPUT -p udp --dport 6000:19999 -j {QUOTA_CHAIN} 2>/dev/null || "
             f"iptables -A INPUT -p udp --dport 6000:19999 -j {QUOTA_CHAIN}"],
            check=False,
        )
    except Exception as e:
        print("ensure_quota_chain error:", e)

def ensure_quota_rule(port: int):
    try:
        ensure_quota_chain()
        cmd = f"iptables -C {QUOTA_CHAIN} -p udp --dport {port} -j RETURN 2>/dev/null"
        r = subprocess.run(["bash", "-lc", cmd], check=False)
        if r.returncode != 0:
            add_cmd = f"iptables -A {QUOTA_CHAIN} -p udp --dport {port} -j RETURN"
            subprocess.run(["bash", "-lc", add_cmd], check=False)
    except Exception as e:
        print("ensure_quota_rule error:", e)

def remove_quota_rule(port: int):
    try:
        cmd = f"iptables -D {QUOTA_CHAIN} -p udp --dport {port} -j RETURN 2>/dev/null"
        subprocess.run(["bash", "-lc", cmd], check=False)
    except Exception as e:
        print("remove_quota_rule error:", e)

def allocate_udp_port():
    ensure_db_ready()
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT udp_port FROM users WHERE udp_port IS NOT NULL")
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        conn.close()
        return PORT_MIN
    conn.close()
    used = {r["udp_port"] for r in rows if r["udp_port"] is not None}
    for p in range(PORT_MIN, PORT_MAX + 1):
        if p not in used:
            return p
    return None

def read_quota_counters():
    counters = {}
    try:
        ensure_quota_chain()
        out = subprocess.check_output(
            ["bash", "-lc", f"iptables -nvx -L {QUOTA_CHAIN} 2>/dev/null || true"]
        ).decode()
        for line in out.splitlines():
            line = line.strip()
            if not line or "dpt:" not in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                bytes_val = int(parts[1])
            except ValueError:
                continue
            port = None
            for tok in parts:
                if tok.startswith("dpt:"):
                    try:
                        port = int(tok.split(":")[1])
                    except ValueError:
                        port = None
                    break
            if port is None:
                continue
            counters[port] = bytes_val
    except Exception as e:
        print("read_quota_counters error:", e)
    return counters

def enforce_quota_once():
    ensure_db_ready()
    counters = read_quota_counters()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, udp_port, quota_gb, used_bytes, expire_at FROM users")
    rows = cur.fetchall()
    now = datetime.datetime.utcnow()
    changed_used = False
    changed_expire = False

    for r in rows:
        uid = r["id"]
        port = r["udp_port"]
        quota = r["quota_gb"]
        used_old = r["used_bytes"] if r["used_bytes"] is not None else 0
        exp = datetime.datetime.fromisoformat(r["expire_at"])

        if port is None:
            continue

        used_bytes_now = counters.get(port, used_old)
        if used_bytes_now != used_old:
            cur.execute("UPDATE users SET used_bytes=? WHERE id=?", (used_bytes_now, uid))
            changed_used = True

        if quota is not None:
            used_gb = used_bytes_now / (1024**3)
            if used_gb >= quota and exp >= now:
                new_exp = (now - datetime.timedelta(seconds=3)).isoformat()
                cur.execute("UPDATE users SET expire_at=? WHERE id=?", (new_exp, uid))
                changed_expire = True

    if changed_used or changed_expire:
        conn.commit()
    conn.close()

    if changed_expire:
        sync_config_with_db()

def enforce_quota_loop():
    while True:
        try:
            enforce_quota_once()
        except Exception as e:
            print("enforce_quota_loop error:", e)
        time.sleep(60)

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

@app.route("/api/users", methods=["GET"])
@login_required
def api_list_users():
    ensure_db_ready()
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
        ensure_db_ready()
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        expire_date_str = (data.get("expire_date") or "").strip()
        quota_str = (data.get("quota_gb") or "").strip()

        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        quota_gb = None
        if quota_str:
            try:
                quota_gb = float(quota_str)
            except ValueError:
                return jsonify({"error": "Invalid quota (GB) value"}), 400

        udp_port = allocate_udp_port()
        if udp_port is None:
            return jsonify({"error": "no free UDP port available"}), 400

        now = datetime.datetime.utcnow()
        created_at = now.isoformat()

        if expire_date_str:
            try:
                expire_date = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d")
            except ValueError:
                return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400
        else:
            expire_date = now + datetime.timedelta(days=30)

        expire_at = expire_date.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password, created_at, expire_at, quota_gb, udp_port, used_bytes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, password, created_at, expire_at, quota_gb, udp_port, 0),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "username already exists"}), 400

        conn.close()
        ensure_quota_rule(udp_port)
        sync_config_with_db()
        return jsonify({"success": True, "udp_port": udp_port})
    except Exception as e:
        print("api_create_user error:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_delete_user(user_id):
    ensure_db_ready()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT udp_port FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    udp_port = row["udp_port"] if row else None
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    if udp_port:
        remove_quota_rule(udp_port)
    sync_config_with_db()
    return jsonify({"success": True})

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def api_update_user(user_id):
    try:
        ensure_db_ready()
        data = request.get_json(silent=True) or request.form
        password = (data.get("password") or "").strip()
        expire_date_str = (data.get("expire_date") or "").strip()
        quota_str = (data.get("quota_gb") or "").strip()

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
                return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400

        if quota_str:
            try:
                quota_gb = float(quota_str)
                fields.append("quota_gb = ?")
                params.append(quota_gb)
            except ValueError:
                return jsonify({"error": "Invalid quota (GB) value"}), 400

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
    except Exception as e:
        print("api_update_user error:", e)
        return jsonify({"error": str(e)}), 500

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
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    ensure_db_ready()
    ensure_quota_chain()
    t = threading.Thread(target=enforce_quota_loop, daemon=True)
    t.start()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

########################################
# 4. FRONTEND (login + panel UI)
########################################
echo
echo "[4/4] Installing Panel UI..."

# login.html
cat << 'EOF' >/usr/local/zivpn-admin/panel/login.html
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

# index.html (main panel)
cat << 'EOF' >/usr/local/zivpn-admin/panel/index.html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZIVPN Admin Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --bg: #020617;
  --bg-card: #020617;
  --bg-card-soft: #020617;
  --text: #e5e7eb;
  --sub: #9ca3af;
  --accent: #22c55e;
  --accent2: #0ea5e9;
  --danger: #ef4444;
  --warning: #eab308;
}
body.light {
  --bg: #e5e7eb;
  --bg-card: #f9fafb;
  --bg-card-soft: #e0f2fe;
  --text: #111827;
  --sub: #6b7280;
}
* { box-sizing:border-box; }
body {
  margin:0;
  font-family: system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background: radial-gradient(circle at top, #1f2937 0, var(--bg) 45%, #000 100%);
  color: var(--text);
}
.main {
  max-width: 900px;
  margin: 16px auto 32px;
  padding: 16px;
}
.card {
  background: var(--bg-card);
  border-radius: 20px;
  padding: 16px 18px;
  box-shadow: 0 18px 40px rgba(0,0,0,0.45);
  border: 1px solid rgba(148,163,184,0.3);
}
.header {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
}
.header-left {
  display:flex;
  align-items:center;
  gap:10px;
}
.logo-circle {
  width:42px;
  height:42px;
  border-radius:999px;
  overflow:hidden;
  box-shadow:0 0 0 3px rgba(34,197,94,0.3);
}
.logo-circle img { width:100%; height:100%; object-fit:cover; }
h1 { margin:0; font-size:1.4rem; }
.ip-box {
  margin-top:10px;
  padding:12px;
  border-radius:16px;
  background: var(--bg-card-soft);
  display:flex;
  flex-direction:column;
  gap:6px;
}
.ip-row {
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:8px;
}
.ip-label { font-size:0.78rem; color:var(--sub); }
.ip-value { font-weight:700; letter-spacing:0.03em; }
.badge {
  padding:4px 10px;
  border-radius:999px;
  font-size:0.7rem;
  border:1px solid rgba(148,163,184,0.6);
}
.badge-green {
  background:#bbf7d0;
  color:#166534;
}
.stats-grid {
  margin-top:16px;
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:12px;
}
.stats-card {
  background: var(--bg-card-soft);
  border-radius:18px;
  padding:10px 12px;
}
.stats-title {
  font-size:0.8rem;
  display:flex;
  align-items:center;
  gap:6px;
  color:var(--sub);
}
.stats-value {
  font-size:2rem;
  font-weight:700;
}
.circle-dot {
  width:13px;
  height:13px;
  border-radius:999px;
  background:#22c55e;
  margin-right:4px;
}
.off-dot { background:#e5e7eb; }
.blink-green { animation: blinkG 1.6s infinite; }
.blink-red { background:#ef4444; animation: blinkR 1.1s infinite; }
.blink-yellow { background:#eab308; animation: blinkY 1.4s infinite; }

@keyframes blinkG {0%,100%{opacity:0.4;}50%{opacity:1;}}
@keyframes blinkR {0%,100%{opacity:0.4;}50%{opacity:1;}}
@keyframes blinkY {0%,100%{opacity:0.4;}50%{opacity:1;}}

.form-section {
  margin-top:18px;
  padding-top:14px;
  border-top:1px dashed rgba(148,163,184,0.4);
}
.field {
  margin-bottom:10px;
}
.field-label {
  font-size:0.8rem;
  margin-bottom:4px;
  color:var(--sub);
  display:flex;
  align-items:center;
  gap:6px;
}
.field-label img { width:18px; height:18px; }
.field-input {
  width:100%;
  border-radius:12px;
  border:1px solid rgba(148,163,184,0.55);
  padding:8px 10px;
  font-size:0.9rem;
  background:var(--bg-card);
  color:var(--text);
}
.field-input:focus { outline:none; border-color:var(--accent2); box-shadow:0 0 0 1px rgba(56,189,248,0.4); }
.btn-main {
  width:100%;
  border:none;
  border-radius:999px;
  padding:10px 12px;
  font-size:1rem;
  font-weight:600;
  color:#fff;
  background:linear-gradient(125deg,#22c55e,#0ea5e9);
  box-shadow:0 18px 35px rgba(0,0,0,0.55);
  cursor:pointer;
  margin-top:4px;
}
.btn-main:active{transform:scale(.99);}
.users-section {
  margin-top:20px;
  padding-top:14px;
  border-top:1px dashed rgba(148,163,184,0.4);
}
.user-card {
  background:var(--bg-card-soft);
  border-radius:18px;
  padding:12px 12px 10px;
  margin-bottom:12px;
  box-shadow:0 12px 24px rgba(0,0,0,0.4);
}
.user-header {
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-bottom:6px;
}
.user-title {
  font-weight:700;
  display:flex;
  align-items:center;
  gap:6px;
}
.user-title-icon {
  width:18px;
  height:18px;
  border-radius:999px;
  background:conic-gradient(from 45deg,#22c55e,#0ea5e9,#6366f1,#ec4899,#22c55e);
}
.user-port {
  font-size:0.7rem;
  padding:4px 10px;
  border-radius:999px;
  border:1px solid rgba(148,163,184,0.7);
  background:#bbf7d0;
  color:#14532d;
}
.user-body {
  display:grid;
  grid-template-columns:1.1fr .9fr;
  gap:6px 10px;
  font-size:0.78rem;
}
.user-label { color:var(--sub); }
.user-value { font-weight:600; word-break:break-all; }
.copy-btn {
  border:none;
  border-radius:999px;
  padding:2px 6px;
  font-size:0.7rem;
  cursor:pointer;
  background:#0ea5e9;
  color:white;
  margin-left:4px;
}
.status-row {
  margin-top:6px;
  display:flex;
  align-items:center;
  gap:6px;
}
.status-text { font-size:0.82rem; font-weight:600; }

.user-actions {
  margin-top:8px;
  display:flex;
  gap:8px;
}
.btn {
  border-radius:999px;
  border:none;
  padding:5px 12px;
  font-size:0.8rem;
  cursor:pointer;
  display:flex;
  align-items:center;
  gap:4px;
}
.btn-edit { background:#0ea5e9; color:white; }
.btn-del  { background:#fee2e2; color:#b91c1c; }
.btn-icon {
  width:16px;
  height:16px;
  border-radius:999px;
  border:1px solid rgba(15,23,42,0.4);
}
.floating-stack {
  position:fixed;
  right:16px;
  top:80px;
  display:flex;
  flex-direction:column;
  gap:10px;
  z-index:50;
}
.float-btn {
  width:50px;
  height:50px;
  border-radius:999px;
  border:none;
  cursor:pointer;
  box-shadow:0 18px 35px rgba(0,0,0,0.65);
  display:flex;
  align-items:center;
  justify-content:center;
}
.float-logout { background:linear-gradient(135deg,#f97316,#ef4444); }
.float-theme  { background:linear-gradient(135deg,#0ea5e9,#22c55e); }
.float-settings{background:linear-gradient(135deg,#22c55e,#22c55e);}
.float-logout img,
.float-theme img,
.float-settings img { width:22px;height:22px; }

.contact-row {
  margin-top:12px;
  font-size:0.8rem;
  display:flex;
  align-items:center;
  gap:8px;
}
.contact-icons {
  display:flex;
  gap:10px;
}
.contact-icons a {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:40px;height:40px;
  border-radius:999px;
  box-shadow:0 10px 22px rgba(0,0,0,0.55);
}
.contact-icons img { width:22px;height:22px; }

.modal-backdrop {
  position:fixed;
  inset:0;
  background:rgba(15,23,42,0.75);
  display:none;
  align-items:center;
  justify-content:center;
  z-index:60;
}
.modal {
  background:var(--bg-card);
  border-radius:18px;
  padding:16px;
  width:90%;
  max-width:380px;
  box-shadow:0 20px 45px rgba(0,0,0,0.8);
  border:1px solid rgba(148,163,184,0.5);
}
.modal h2 {
  margin:0 0 8px;
  font-size:1.1rem;
}
.modal p {
  margin:0 0 10px;
  font-size:0.8rem;
  color:var(--sub);
}
.modal .field-input { margin-bottom:8px; }
.modal-buttons {
  margin-top:8px;
  display:flex;
  justify-content:flex-end;
  gap:8px;
}
.btn-sm {
  border-radius:999px;
  border:none;
  padding:6px 12px;
  font-size:0.8rem;
  cursor:pointer;
}
.btn-cancel { background:rgba(148,163,184,0.15); color:var(--sub); }
.btn-save { background:linear-gradient(135deg,#22c55e,#0ea5e9); color:#fff; }

.server-mini {
  margin-top:10px;
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:6px;
  font-size:0.75rem;
}
.server-chip {
  background:rgba(15,23,42,0.35);
  border-radius:999px;
  padding:4px 8px;
  display:flex;
  flex-direction:column;
}
.server-chip span:nth-child(1){color:var(--sub);}
.server-chip span:nth-child(2){font-weight:600;}

@media (max-width:600px){
  .header{flex-direction:column;align-items:flex-start;}
  .user-body{grid-template-columns:1.1fr .9fr;}
}
</style>
</head>
<body>
<div class="floating-stack">
  <button class="float-settings float-btn" onclick="openSettings()">
    <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/setting.png" alt="settings">
  </button>
  <button class="float-theme float-btn" onclick="toggleTheme()">
    <img id="themeIcon" src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/sun.png" alt="theme">
  </button>
  <button class="float-logout float-btn" onclick="doLogout()">
    <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/lock.png" alt="logout">
  </button>
</div>

<div class="main">
  <div class="card">
    <div class="header">
      <div class="header-left">
        <div class="logo-circle">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN">
        </div>
        <div>
          <h1>ZIVPN Admin Panel</h1>
          <div style="font-size:0.75rem;color:var(--sub);">Control your ZIVPN UDP users with live cards.</div>
        </div>
      </div>
    </div>

    <div class="ip-box">
      <div class="ip-row">
        <div>
          <div class="ip-label">VPS IP</div>
          <div class="ip-value" id="vpsIp">0.0.0.0</div>
        </div>
        <div>
          <div class="badge badge-green" id="udpPortBadge">UDP :5667</div>
          <div class="ip-label" id="panelUrl">Admin Panel: -</div>
        </div>
      </div>
      <div class="server-mini">
        <div class="server-chip">
          <span>CPU</span><span id="cpuStat">-</span>
        </div>
        <div class="server-chip">
          <span>RAM</span><span id="ramStat">-</span>
        </div>
        <div class="server-chip">
          <span>Storage</span><span id="diskStat">-</span>
        </div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stats-card">
        <div class="stats-title">
          <span style="font-size:1rem;">👥</span>
          <span>Total Users</span>
        </div>
        <div class="stats-value" id="totalUsers">0</div>
      </div>
      <div class="stats-card">
        <div class="stats-title">
          <span class="circle-dot blink-green"></span>
          <span>Online</span>
        </div>
        <div class="stats-value" id="onlineUsers">0</div>
      </div>
      <div class="stats-card">
        <div class="stats-title">
          <span class="circle-dot off-dot"></span>
          <span>Offline</span>
        </div>
        <div class="stats-value" id="offlineUsers">0</div>
      </div>
    </div>

    <div class="form-section">
      <div class="field">
        <div class="field-label">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/user.png" alt="">
          <span>Username</span>
        </div>
        <input class="field-input" id="usernameInput" placeholder="Enter username">
      </div>
      <div class="field">
        <div class="field-label">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/key.png" alt="">
          <span>Password</span>
        </div>
        <input class="field-input" id="passwordInput" placeholder="Enter password">
      </div>
      <div class="field">
        <div class="field-label">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/gb.png" alt="">
          <span>Total Flow (GB)</span>
        </div>
        <input class="field-input" id="quotaInput" placeholder="e.g. 100 (optional)">
      </div>
      <div class="field">
        <div class="field-label">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/cal.png" alt="">
          <span>Custom Expire Date</span>
        </div>
        <input class="field-input" type="date" id="dateInput">
      </div>
      <button class="btn-main" onclick="addAccount()">+ Add Account</button>
    </div>

    <div class="users-section">
      <div id="usersContainer"></div>
    </div>

    <div class="contact-row">
      <span>Contact :</span>
      <div class="contact-icons">
        <a href="https://t.me/Pussy1990" target="_blank" style="background:#0f172a;">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/t.png" alt="TG">
        </a>
        <a href="https://www.facebook.com/juehtet2025" target="_blank" style="background:#0f172a;">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/f.png" alt="FB">
        </a>
        <a href="https://m.me/juehtet2025" target="_blank" style="background:#0f172a;">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/m.png" alt="MS">
        </a>
      </div>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="settingsModal">
  <div class="modal">
    <h2>Change Admin Login</h2>
    <p>Change admin username/password without reinstall.</p>
    <div class="field">
      <div class="field-label"><span>Current Password</span></div>
      <input class="field-input" id="oldAdminPass" type="password" placeholder="Old admin password">
    </div>
    <div class="field">
      <div class="field-label"><span>New Username</span></div>
      <input class="field-input" id="newAdminUser" placeholder="New username (optional)">
    </div>
    <div class="field">
      <div class="field-label"><span>New Password</span></div>
      <input class="field-input" id="newAdminPass" type="password" placeholder="New password (optional)">
    </div>
    <div class="modal-buttons">
      <button class="btn-sm btn-cancel" onclick="closeSettings()">Cancel</button>
      <button class="btn-sm btn-save" onclick="saveAdmin()">Save</button>
    </div>
  </div>
</div>

<script>
let serverInfo = null;

function toggleTheme() {
  document.body.classList.toggle('light');
  const icon = document.getElementById('themeIcon');
  if (document.body.classList.contains('light')) {
    icon.src = "https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/moon.png";
  } else {
    icon.src = "https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/sun.png";
  }
}

function doLogout() {
  if (confirm("Logout from Admin Panel?")) {
    window.location.href = "/logout";
  }
}

function openSettings(){
  document.getElementById('settingsModal').style.display = 'flex';
}
function closeSettings(){
  document.getElementById('settingsModal').style.display = 'none';
}

async function saveAdmin(){
  const oldPass = document.getElementById('oldAdminPass').value;
  const newUser = document.getElementById('newAdminUser').value;
  const newPass = document.getElementById('newAdminPass').value;
  if (!oldPass) {
    alert("Enter current admin password.");
    return;
  }
  try{
    const res = await fetch("/api/admin",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        old_password:oldPass,
        new_username:newUser,
        new_password:newPass
      })
    });
    const data = await res.json();
    if(res.ok && data.success){
      alert("Admin login updated. Please re-login.");
      window.location.href="/logout";
    }else{
      alert("Failed to update admin: " + (data.error || "Unknown error"));
    }
  }catch(e){
    alert("Request error: " + e);
  }
}

function copyText(text){
  navigator.clipboard.writeText(text || "").then(()=>{
    // optional toast
  });
}

function createStatusDot(status){
  const span = document.createElement('span');
  span.className = "circle-dot";
  if(status === "Online"){
    span.classList.add('blink-green');
  }else if(status === "Expiring"){
    span.classList.add('blink-yellow');
  }else{
    span.classList.add('blink-red');
  }
  return span;
}

async function loadServer(){
  try{
    const res = await fetch("/api/server");
    const data = await res.json();
    serverInfo = data;
    document.getElementById("vpsIp").textContent = data.ip;
    document.getElementById("udpPortBadge").textContent = "UDP :" + data.udp_port;
    document.getElementById("udpPortBadge").style.background="#bbf7d0";
    document.getElementById("udpPortBadge").style.color="#166534";
    document.getElementById("panelUrl").textContent = "Admin Panel: " + data.ip + ":" + data.panel_port;
    document.getElementById("cpuStat").textContent = (data.cpu_percent ?? "-") + "%";
    if(data.mem_total_gb!=null && data.mem_used_percent!=null){
      document.getElementById("ramStat").textContent = data.mem_used_percent + "% of " + data.mem_total_gb + "GB";
    }else{
      document.getElementById("ramStat").textContent = "-";
    }
    if(data.disk_total_gb!=null && data.disk_used_percent!=null){
      document.getElementById("diskStat").textContent = data.disk_used_percent + "% of " + data.disk_total_gb + "GB";
    }else{
      document.getElementById("diskStat").textContent = "-";
    }
  }catch(e){
    console.error(e);
  }
}

function statusLabel(u){
  if(u.status === "Expiring") return "Expiring";
  return u.status;
}

async function loadUsers(){
  try{
    const res = await fetch("/api/users");
    const data = await res.json();
    document.getElementById("totalUsers").textContent = data.total;
    document.getElementById("onlineUsers").textContent = data.online;
    document.getElementById("offlineUsers").textContent = data.offline;

    const c = document.getElementById("usersContainer");
    c.innerHTML = "";
    data.users.forEach(u=>{
      const card = document.createElement("div");
      card.className = "user-card";

      const header = document.createElement("div");
      header.className = "user-header";

      const title = document.createElement("div");
      title.className = "user-title";
      const icon = document.createElement("div");
      icon.className = "user-title-icon";
      title.appendChild(icon);
      const name = document.createElement("span");
      name.textContent = u.username;
      title.appendChild(name);

      const port = document.createElement("div");
      port.className = "user-port";
      port.textContent = "PORT " + (u.udp_port || 5667);
      header.appendChild(title);
      header.appendChild(port);

      const body = document.createElement("div");
      body.className = "user-body";

      function addRow(label,val,copyable){
        const l = document.createElement("div");
        l.className = "user-label";
        l.textContent = label;
        const v = document.createElement("div");
        v.className = "user-value";
        v.textContent = val;
        if(copyable){
          const b = document.createElement("button");
          b.className = "copy-btn";
          b.textContent = "📋";
          b.onclick = ()=>copyText(val);
          v.appendChild(b);
        }
        body.appendChild(l);
        body.appendChild(v);
      }

      addRow("VPS IP", serverInfo ? serverInfo.ip : "-", true);
      addRow("Username", u.username, true);
      addRow("Password", u.password, true);
      addRow("Day Left", u.day_left + " Days", false);
      addRow("Expire Date", u.expire_at, false);
      if(u.quota_gb!=null){
        addRow("Total Flow", u.quota_gb + " GB", false);
      }
      if(u.used_gb!=null && u.quota_gb!=null){
        addRow("Used / Left", u.used_gb + " / " + u.left_gb + " GB", false);
      }

      const statusRow = document.createElement("div");
      statusRow.className = "status-row";
      const dot = createStatusDot(u.status);
      statusRow.appendChild(dot);
      const st = document.createElement("span");
      st.className = "status-text";
      st.textContent = statusLabel(u);
      statusRow.appendChild(st);

      const actions = document.createElement("div");
      actions.className = "user-actions";

      const edit = document.createElement("button");
      edit.className = "btn btn-edit";
      edit.innerHTML = '<span class="btn-icon"></span>Edit';
      edit.onclick = ()=>editUser(u);
      const del = document.createElement("button");
      del.className = "btn btn-del";
      del.innerHTML = '<span class="btn-icon"></span>Delete';
      del.onclick = ()=>deleteUser(u);

      actions.appendChild(edit);
      actions.appendChild(del);

      card.appendChild(header);
      card.appendChild(body);
      card.appendChild(statusRow);
      card.appendChild(actions);
      c.appendChild(card);
    });
  }catch(e){
    console.error(e);
  }
}

async function addAccount(){
  const u = document.getElementById("usernameInput").value.trim();
  const p = document.getElementById("passwordInput").value.trim();
  const q = document.getElementById("quotaInput").value.trim();
  const d = document.getElementById("dateInput").value;

  if(!u || !p){
    alert("Please enter Username and Password.");
    return;
  }

  try{
    const res = await fetch("/api/users",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        username:u,
        password:p,
        expire_date:d,
        quota_gb:q
      })
    });
    const data = await res.json();
    if(res.ok && data.success){
      const dayLeft = 0; // UI only; real value reload မှာ ပြန်ထုတ်မယ်
      const ip = serverInfo ? serverInfo.ip : "-";
      alert(
        "Create Account Successfully ✅\n\n" +
        "IP: " + ip + "\n" +
        "User: " + u + "\n" +
        "Pass: " + p + "\n" +
        "Expire: " + (d || "Auto 30 days")
      );
      document.getElementById("usernameInput").value="";
      document.getElementById("passwordInput").value="";
      document.getElementById("quotaInput").value="";
      loadUsers();
    }else{
      alert("Failed to create user" + (data.error ? " : " + data.error : ""));
    }
  }catch(e){
    alert("Request error: " + e);
  }
}

async function deleteUser(u){
  if(!confirm("Delete user "+u.username+" ?")) return;
  try{
    const res = await fetch("/api/users/"+u.id,{method:"DELETE"});
    const data = await res.json();
    if(res.ok && data.success){
      loadUsers();
    }else{
      alert("Failed to delete user");
    }
  }catch(e){
    alert("Request error: "+e);
  }
}

async function editUser(u){
  const newPass = prompt("New password for "+u.username+" (leave blank = no change):","");
  if(newPass===null) return;
  const newDate = prompt("New expire date YYYY-MM-DD (leave blank = no change):","");
  const newQuota = prompt("New Total Flow GB (leave blank = no change):","");
  try{
    const res = await fetch("/api/users/"+u.id,{
      method:"PUT",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        password:newPass,
        expire_date:newDate,
        quota_gb:newQuota
      })
    });
    const data = await res.json();
    if(res.ok && data.success){
      loadUsers();
    }else{
      alert("Failed to update user: " + (data.error || ""));
    }
  }catch(e){
    alert("Request error: " + e);
  }
}

window.addEventListener("DOMContentLoaded",()=>{
  const today = new Date().toISOString().slice(0,10);
  document.getElementById("dateInput").value = today;
  loadServer();
  loadUsers();
});
</script>
</body>
</html>
EOF

########################################
# SYSTEMD SERVICE FOR PANEL
########################################
cat <<EOF >/etc/systemd/system/zivpn-admin.service
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
systemctl restart zivpn-admin.service

SERVER_IP=$(hostname -I | awk '{print $1}')

BLUE="\e[34m"
NC="\e[0m"

echo
echo -e "${BLUE}========================================"
echo -e " ZIVPN UDP & Admin Panel Installed"
echo -e " (Port per User + Flow Quota)"
echo -e "----------------------------------------"
echo -e " VPS IP        : ${SERVER_IP}"
echo -e " Admin Panel   : http://${SERVER_IP}:8989"
echo -e " UDP Port      : 5667"
echo -e "----------------------------------------"
echo -e " Admin USER    : ${ADMIN_USER}"
echo -e " Admin PASS    : ${ADMIN_PASS}"
echo -e " Script Owner By: JueHtet"
echo -e "========================================${NC}"
