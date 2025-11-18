#!/bin/bash
# ZIVPN UDP + Admin Panel One-Click Installer
# Port per User + Per-User UDP Password + Quota System
# Status = Expire Date only (Online/Expiring/Offline)
# Quota = Per-user Port + iptables Counters (NAT/PREROUTING)
# Script Owner By: JueHtet
# Engine v2 (Per-User Password Mode, restart required)

set -e
export LC_ALL=C

clear
echo "=============================================="
echo "   ZIVPN UDP + Admin Panel Auto Installer"
echo "   (Per-User UDP Password + Quota System)"
echo "=============================================="
echo

echo "[0/4] System update & base packages..."
apt-get update -y
# server reset မကျအောင် upgrade မလုပ်တော့
# apt-get upgrade -y
apt-get install -y sudo curl wget python3 python3-venv python3-pip sqlite3 ufw conntrack iproute2

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

# Installer default fallback password (no user or all expired)
echo
read -p "Default UDP fallback password (used when no active user, default: zi): " INSTALL_FALLBACK_PW
[ -z "$INSTALL_FALLBACK_PW" ] && INSTALL_FALLBACK_PW="zi"

# Rewrite auth section in config.json for password list mode
# We also store fallback in "fallback" key (zivpn ignores it; our panel uses it)
python3 - "$INSTALL_FALLBACK_PW" << 'PYEOF'
import json, sys
path = "/etc/zivpn/config.json"
fallback = sys.argv[1]
try:
    with open(path, "r") as f:
        data = json.load(f)
except Exception:
    data = {}
auth = data.get("auth", {})
auth["mode"] = "passwords"
# initial config list has only fallback; panel will overwrite later.
auth["config"] = [fallback]
auth["fallback"] = fallback
data["auth"] = auth
with open(path, "w") as f:
    json.dump(data, f)
PYEOF

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

systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

# NAT + QUOTA chain (NAT/PREROUTING)
DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
if [ -n "$DEV" ]; then
  # create quota chain
  iptables -t nat -N ZIVPN_QUOTA 2>/dev/null || true

  # remove old rules if any
  iptables -t nat -D PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j ZIVPN_QUOTA 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || true

  # 1) count usage in quota chain
  iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j ZIVPN_QUOTA
  # 2) DNAT all per-user ports to main port 5667
  iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
  # 3) return traffic (optional but safe)
  iptables -t nat -A POSTROUTING -p udp --sport 5667 -j MASQUERADE 2>/dev/null || true
fi

ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

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

# ------------------ DB & ADMIN CREDS ------------------ #
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # fresh schema
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE,"
        "password TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "expire_at TEXT NOT NULL,"
        "quota_gb REAL,"
        "udp_port INTEGER UNIQUE,"
        "used_bytes INTEGER DEFAULT 0"
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

# ------------------ SERVER INFO & STATS ------------------ #
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

# ------------------ USER MODEL ------------------ #
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

# ------------------ CONFIG SYNC (PER-USER PASSWORD) ------------------ #
def load_fallback_password():
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        auth = data.get("auth", {})
        fb = auth.get("fallback") or "zi"
        return fb
    except Exception:
        return "zi"

def sync_config_with_db():
    """
    Read all users from DB. Active users (not expired) → their password
    list becomes auth.config in /etc/zivpn/config.json.
    Then restart zivpn.service (per-user password mode).
    """
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password, expire_at FROM users")
        rows = cur.fetchall()
        conn.close()

        now = datetime.datetime.utcnow()
        passwords = []
        for r in rows:
            exp = datetime.datetime.fromisoformat(r["expire_at"])
            if exp >= now:
                pw = r["password"]
                if pw not in passwords:
                    passwords.append(pw)

        fb = load_fallback_password()
        if not passwords:
            passwords = [fb]

        if not os.path.exists(CONFIG_PATH):
            return

        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)

        auth = data.get("auth", {})
        auth["mode"] = "passwords"
        auth["config"] = passwords
        if "fallback" not in auth:
            auth["fallback"] = fb
        data["auth"] = auth

        with open(CONFIG_PATH, "w") as f:
            json.dump(data, f)

        # restart UDP server to apply password list
        subprocess.run(["systemctl", "restart", "zivpn.service"], check=False)
    except Exception as e:
        print("sync_config_with_db error:", e)

# ------------------ QUOTA / IPTABLES HELPERS ------------------ #
def ensure_quota_chain():
    try:
        cmd = (
            f"iptables -t nat -N {QUOTA_CHAIN} 2>/dev/null || true; "
            f"iptables -t nat -C PREROUTING -p udp --dport 6000:19999 -j {QUOTA_CHAIN} 2>/dev/null || "
            f"iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j {QUOTA_CHAIN}"
        )
        subprocess.run(["bash", "-lc", cmd], check=False)
    except Exception as e:
        print("ensure_quota_chain error:", e)

def ensure_quota_rule(port: int):
    try:
        ensure_quota_chain()
        cmd = f"iptables -t nat -C {QUOTA_CHAIN} -p udp --dport {port} -j RETURN 2>/dev/null"
        r = subprocess.run(["bash", "-lc", cmd], check=False)
        if r.returncode != 0:
            add_cmd = f"iptables -t nat -A {QUOTA_CHAIN} -p udp --dport {port} -j RETURN"
            subprocess.run(["bash", "-lc", add_cmd], check=False)
    except Exception as e:
        print("ensure_quota_rule error:", e)

def remove_quota_rule(port: int):
    try:
        cmd = f"iptables -t nat -D {QUOTA_CHAIN} -p udp --dport {port} -j RETURN 2>/dev/null"
        subprocess.run(["bash", "-lc", cmd], check=False)
    except Exception as e:
        print("remove_quota_rule error:", e)

def allocate_udp_port():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT udp_port FROM users WHERE udp_port IS NOT NULL")
    rows = cur.fetchall()
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
            ["bash", "-lc", f"iptables -t nat -nvx -L {QUOTA_CHAIN} 2>/dev/null || true"]
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
    counters = read_quota_counters()
    if not counters:
        return
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
        # quota လွန်းသွားလို့ expire ပြောင်းရင် password list ကိုလည်း refresh
        sync_config_with_db()

def enforce_quota_loop():
    while True:
        try:
            enforce_quota_once()
        except Exception as e:
            print("enforce_quota_loop error:", e)
        time.sleep(60)

# ------------------ ROUTES ------------------ #
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
            quota_gb = None

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
            "INSERT INTO users (username, password, created_at, expire_at, quota_gb, udp_port, used_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, password, created_at, expire_at, quota_gb, udp_port, 0),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close>
        return jsonify({"error": "username already exists"}), 400

    conn.close()
    ensure_quota_rule(udp_port)
    sync_config_with_db()
    return jsonify({"success": True, "udp_port": udp_port})

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_delete_user(user_id):
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
    data = request.get_json(silent=True) or request.form
    password = (data.get("password") or "").strip()
    expire_date_str = (data.get("expire_date") or "").strip()
    quota_str = (data.get("quota_gb") or "").strip()

    fields = []
    params = []

    pw_changed = False

    if password:
        fields.append("password = ?")
        params.append(password)
        pw_changed = True

    if expire_date_str:
        try:
            expire_date = datetime.datetime.strptime(expire_date_str, "%Y-%m-%d")
            expire_at = expire_date.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
            fields.append("expire_at = ?")
            params.append(expire_at)
        except ValueError:
            pass

    if quota_str:
        try:
            quota_gb = float(quota_str)
            fields.append("quota_gb = ?")
            params.append(quota_gb)
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
    # password / expire change → password list refresh
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
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    init_db()
    ensure_quota_chain()
    t = threading.Thread(target=enforce_quota_loop, daemon=True)
    t.start()
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
EOF

chmod +x /usr/local/zivpn-admin/server.py

########################################
# 4. FRONTEND (login.html + index.html)
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

# ---- index.html ----
cat << 'EOF' > /usr/local/zivpn-admin/panel/index.html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ZIVPN Admin Panel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body {
      margin: 0;
      padding: 0;
      background: radial-gradient(circle at top, #1f2937 0, #020617 45%, #000 100%);
      color: #e5e7eb;
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
    .vps-box {
      padding: 10px 12px;
      border-radius: 14px;
      background: rgba(15,23,42,0.95);
      border: 1px solid rgba(148,163,184,0.45);
      margin-bottom: 14px;
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
    }
    .stat-label {
      color:#9ca3af;
      margin-bottom:2px;
    }
    .stat-value {
      font-size:0.9rem;
      font-weight:600;
    }
    .form-row {
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      margin-bottom:14px;
    }
    .input-wrap {
      flex:1 1 160px;
      min-width:140px;
      display:flex;
      flex-direction:column;
      gap:4px;
    }
    .input-wrap span.icon {
      font-size:0.8rem;
      color:#9ca3af;
    }
    .input-wrap input {
      width:100%;
      padding:7px 9px;
      border-radius:10px;
      border:1px solid rgba(148,163,184,0.6);
      background:rgba(15,23,42,0.95);
      color:#e5e7eb;
      font-size:0.85rem;
    }
    .btn {
      border-radius:999px;
      border:none;
      padding:7px 14px;
      font-size:0.85rem;
      display:inline-flex;
      align-items:center;
      gap:6px;
      cursor:pointer;
      background:linear-gradient(135deg,#22c55e,#0ea5e9);
      color:#020617;
      font-weight:600;
      box-shadow:0 14px 30px rgba(0,0,0,0.7);
      white-space:nowrap;
    }
    .btn-sm {
      padding:4px 9px;
      font-size:0.78rem;
      box-shadow:none;
    }
    .btn-ghost {
      background:transparent;
      border:1px solid rgba(148,163,184,0.6);
      color:inherit;
    }
    .btn-danger {
      background:rgba(239,68,68,0.12);
      border:1px solid rgba(248,113,113,0.8);
      color:#fecaca;
    }
    .users-grid {
      display:grid;
      grid-template-columns:repeat(auto-fill,minmax(260px,1fr));
      gap:10px;
      margin-top:6px;
    }
    .user-card {
      background:rgba(15,23,42,0.98);
      border-radius:14px;
      border:1px solid rgba(55,65,81,0.9);
      padding:10px 10px;
      font-size:0.78rem;
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
    .badge-port {
      font-size:0.7rem;
      border-radius:999px;
      padding:2px 7px;
      border:1px solid rgba(34,197,94,0.9);
      color:#bbf7d0;
      background:rgba(22,163,74,0.18);
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
    .field-value {
      font-weight:500;
      display:flex;
      align-items:center;
      gap:3px;
    }
    .status-dot {
      width:7px;
      height:7px;
      border-radius:999px;
      display:inline-block;
      margin-right:4px;
    }
    .status-online {
      background:#22c55e;
      box-shadow:0 0 7px rgba(34,197,94,0.8);
    }
    .status-warning {
      background:#eab308;
      box-shadow:0 0 7px rgba(234,179,8,0.8);
    }
    .status-offline {
      background:#ef4444;
      box-shadow:0 0 6px rgba(248,113,113,0.8);
    }
    .actions {
      display:flex;
      gap:4px;
      margin-top:6px;
    }
    .logout-fab {
      position:fixed;
      top:14px;
      right:14px;
      width:40px;
      height:40px;
      border-radius:999px;
      display:flex;
      align-items:center;
      justify-content:center;
      background:linear-gradient(135deg,#f97316,#ef4444);
      color:#0b1120;
      text-decoration:none;
      font-size:1.1rem;
      box-shadow:0 14px 30px rgba(0,0,0,0.85);
      border:1px solid rgba(248,250,252,0.7);
      z-index:50;
    }
    .copy-btn {
      border:none;
      background:transparent;
      cursor:pointer;
      font-size:0.78rem;
      padding:0 3px;
    }
  </style>
</head>
<body>
  <a href="/logout" class="logout-fab" title="Logout">🔒</a>
  <div class="container">
    <div class="card">
      <h1>
        <span class="logo">
          <img src="https://raw.githubusercontent.com/JVPNSHOP/Admin-Zivpn/main/image/z.png" alt="ZIVPN">
        </span>
        <span>ZIVPN Admin Panel</span>
      </h1>

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
            <span class="icon">👤 Username</span>
            <input id="username" name="username" placeholder="Enter username">
          </div>
          <div class="input-wrap">
            <span class="icon">🔑 UDP Password (Per User)</span>
            <input id="password" name="password" placeholder="Enter UDP password">
          </div>
          <div class="input-wrap">
            <span class="icon">📊 Total Flow (GB)</span>
            <input id="quota_gb" name="quota_gb" placeholder="e.g. 50">
          </div>
          <div class="input-wrap">
            <span class="icon">📅 Expire Date</span>
            <input id="expire_date" name="expire_date" type="date">
          </div>
          <button class="btn" type="submit">
            <span>➕</span> Add Account
          </button>
        </div>
      </form>

      <div id="users-wrap" class="users-grid"></div>
    </div>
  </div>

  <script>
    let serverIpCache = null;

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

        const cpu = data.cpu_percent != null ? data.cpu_percent + '%' : '-';
        const ram = (data.mem_used_percent != null && data.mem_total_gb != null)
          ? `${data.mem_used_percent}% of ${data.mem_total_gb} GB`
          : '-';
        const disk = (data.disk_used_percent != null && data.disk_total_gb != null)
          ? `${data.disk_used_percent}% of ${data.disk_total_gb} GB`
          : '-';
        document.getElementById('stat-cpu').textContent = cpu;
        document.getElementById('stat-ram').textContent = ram;
        document.getElementById('stat-disk').textContent = disk;
      } catch (e) {
        document.getElementById('server-ip').textContent = 'Unknown';
      }
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

        let statusDotClass = 'status-offline';
        if (u.status === 'Online') statusDotClass = 'status-online';
        else if (u.status === 'Expiring') statusDotClass = 'status-warning';

        const quotaText = (u.quota_gb != null) ? (u.quota_gb + ' GB') : '-';
        const usedText = (u.used_gb != null) ? (u.used_gb.toFixed(3) + ' GB') : '0 GB';
        const leftText = (u.left_gb != null) ? (u.left_gb.toFixed(3) + ' GB') : '-';
        const portText = u.udp_port != null ? u.udp_port : '-';

        card.innerHTML = `
          <div class="user-header">
            <div class="user-title">
              <span>${u.username}</span>
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
              ${u.username}
              <button class="copy-btn" type="button" onclick="copyText('${u.username}')">📋</button>
            </span>
          </div>
          <div class="field-row">
            <span class="field-label">UDP Password</span>
            <span class="field-value">
              ${u.password}
              <button class="copy-btn" type="button" onclick="copyText('${u.password}')">📋</button>
            </span>
          </div>
          <div class="field-row">
            <span class="field-label">Total Flow</span>
            <span class="field-value">${quotaText}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Used</span>
            <span class="field-value">${usedText}</span>
          </div>
          <div class="field-row">
            <span class="field-label">Left</span>
            <span class="field-value">${leftText}</span>
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
            <span class="field-value">
              <span class="status-dot ${statusDotClass}"></span>${u.status}
            </span>
          </div>
          <div class="actions">
            <button class="btn btn-sm btn-ghost" type="button"
              onclick='editUser(${u.id},"${u.username}","${u.password}","${u.expire_at}",${u.quota_gb==null?"null":u.quota_gb})'>✏ Edit</button>
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
      const quota_gb = document.getElementById('quota_gb').value.trim();
      const expire_date = document.getElementById('expire_date').value.trim();

      if (!username || !password) {
        alert('Username & UDP Password required');
        return;
      }

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, expire_date, quota_gb })
        });
        const data = await res.json();
        if (data.error) {
          alert(data.error);
        } else {
          alert('User created. UDP server restarting 1 sec for password apply.');
          document.getElementById('username').value = '';
          document.getElementById('password').value = '';
          document.getElementById('quota_gb').value = '';
          setDefaultDate();
          fetchUsers();
        }
      } catch (e) {
        alert('Failed to create user');
      }
    }

    async function deleteUser(id) {
      if (!confirm('Delete this user? (UDP server will restart)')) return;
      try {
        const res = await fetch('/api/users/' + id, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
          alert('User deleted. UDP server restarting...');
          fetchUsers();
        }
      } catch (e) {
        alert('Failed to delete user');
      }
    }

    async function editUser(id, username, oldPass, oldDate, oldQuota) {
      const newPass = prompt('New UDP password for ' + username + ' (blank = keep same):', oldPass);
      const newDate = prompt('New expire date (YYYY-MM-DD, blank = keep same):', oldDate);
      const newQuota = prompt('Total Flow in GB (blank = keep same):', oldQuota == null ? '' : oldQuota);

      if (newPass === null && newDate === null && newQuota === null) return;

      const payload = {};
      if (newPass !== null && newPass !== oldPass && newPass !== '') payload.password = newPass;
      if (newDate !== null && newDate !== oldDate && newDate !== '') payload.expire_date = newDate;
      if (newQuota !== null && newQuota !== '' && newQuota !== String(oldQuota)) payload.quota_gb = newQuota;

      if (Object.keys(payload).length === 0) return;

      try {
        const res = await fetch('/api/users/' + id, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.error) {
          alert(data.error);
        } else {
          alert('User updated. UDP server restarting if password/expire changed.');
          fetchUsers();
        }
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
echo -e " (Per-User UDP Password + Quota System)"
echo -e "----------------------------------------"
echo -e " VPS IP        : ${SERVER_IP}"
echo -e " Admin Panel   : http://${SERVER_IP}:8989"
echo -e " UDP Port      : 5667"
echo -e "----------------------------------------"
echo -e " Admin USER    : ${ADMIN_USER}"
echo -e " Admin PASS    : ${ADMIN_PASS}"
echo -e "----------------------------------------"
echo -e " NOTE: User add/delete/password change"
echo -e "       → UDP server auto restart 1 sec"
echo -e "========================================${NC}"
