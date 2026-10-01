import os
import sys
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
import re
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from threading import Thread
from functools import wraps

# Install dependencies
required = ['flask', 'flask-cors', 'flask-socketio', 'flask-login', 'bcrypt', 'eventlet']
for pkg in required:
    try:
        __import__(pkg.replace('-', '_'))
    except ImportError:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

from flask import Flask, jsonify, request, render_template_string, redirect, url_for, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt

# Setup paths
DESKTOP_PATH = os.path.join(os.path.expanduser("~"), "Desktop", "Windows-SIEM")
os.makedirs(DESKTOP_PATH, exist_ok=True)
DB_PATH = os.path.join(DESKTOP_PATH, "siem.db")

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_analyst(self):
        return self.role == 'analyst'

# Database functions
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY, timestamp TEXT, event_id INTEGER,
        level TEXT, source TEXT, channel TEXT, message TEXT,
        username TEXT, computer TEXT, processed INTEGER DEFAULT 0)''')
    
    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY, timestamp TEXT, severity TEXT,
        title TEXT, description TEXT, rule_name TEXT, username TEXT,
        event_id INTEGER, mitre_tactic TEXT, acknowledged INTEGER DEFAULT 0)''')
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, 
        password_hash TEXT, role TEXT, created_at TEXT)''')
    
    conn.commit()
    conn.close()
    
    # Create default users
    create_default_users()

def create_default_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if users exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # Create admin user
        admin_hash = bcrypt.hashpw(b'admin123', bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                  ('admin', admin_hash, 'admin', datetime.now().isoformat()))
        
        # Create analyst user
        analyst_hash = bcrypt.hashpw(b'analyst123', bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                  ('analyst', analyst_hash, 'analyst', datetime.now().isoformat()))
        
        conn.commit()
        print("\n" + "="*50)
        print("DEFAULT USERS CREATED:")
        print("  Admin:    username=admin,    password=admin123")
        print("  Analyst:  username=analyst,  password=analyst123")
        print("="*50 + "\n")
    
    conn.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1], row[3])
    return None

def verify_password(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return bcrypt.checkpw(password.encode(), row[0])
    return False

# Login manager
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1], row[3])
    return None

# Role decorator
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Log functions
def add_log(d):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO logs (timestamp,event_id,level,source,channel,message,username,computer) 
                 VALUES (?,?,?,?,?,?,?,?)""",
              (d.get('timestamp'), d.get('event_id'), d.get('level'), 
               d.get('source'), d.get('channel'), d.get('message'),
               d.get('username'), d.get('computer')))
    conn.commit()
    conn.close()

def add_alert(d):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO alerts (timestamp,severity,title,description,rule_name,username,event_id,mitre_tactic) 
                 VALUES (?,?,?,?,?,?,?,?)""",
              (datetime.now().isoformat(), d.get('severity'), d.get('title'),
               d.get('description'), d.get('rule_name'), d.get('username'),
               d.get('event_id'), d.get('mitre_tactic')))
    conn.commit()
    alert_id = c.lastrowid
    conn.close()
    return alert_id

def get_logs(limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    r = [dict(x) for x in c.fetchall()]
    conn.close()
    return r

def get_alerts(acknowledged=None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if acknowledged is not None:
        c.execute("SELECT * FROM alerts WHERE acknowledged=? ORDER BY timestamp DESC", (1 if acknowledged else 0,))
    else:
        c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    r = [dict(x) for x in c.fetchall()]
    conn.close()
    return r

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs")
    tl = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0")
    aa = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts")
    ta = c.fetchone()[0]
    
    # Get hourly stats
    c.execute("""SELECT strftime('%H', timestamp) as hour, COUNT(*) as count 
                 FROM logs WHERE timestamp > datetime('now', '-24 hours')
                 GROUP BY hour ORDER BY hour""")
    hourly = [{'hour': r[0], 'count': r[1]} for r in c.fetchall()]
    
    # Get severity distribution
    c.execute("""SELECT severity, COUNT(*) as count FROM alerts 
                 WHERE timestamp > datetime('now', '-24 hours')
                 GROUP BY severity""")
    severity = [{'severity': r[0], 'count': r[1]} for r in c.fetchall()]
    
    # Get top event sources
    c.execute("""SELECT source, COUNT(*) as count FROM logs 
                 WHERE timestamp > datetime('now', '-24 hours')
                 GROUP BY source ORDER BY count DESC LIMIT 10""")
    sources = [{'source': r[0], 'count': r[1]} for r in c.fetchall()]
    
    conn.close()
    return {
        'total_logs': tl, 'active_alerts': aa, 'total_alerts': ta,
        'hourly': hourly, 'severity': severity, 'sources': sources
    }

def ack_alert(aid):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (aid,))
    conn.commit()
    conn.close()

def ack_all():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE alerts SET acknowledged=1")
    conn.commit()
    conn.close()

def mark_processed():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE logs SET processed=1 WHERE processed=0")
    conn.commit()
    conn.close()

# Event collection
def collect():
    total = 0
    for ch in ['Security', 'System', 'Application']:
        try:
            r = subprocess.run(f'wevtutil qe "{ch}" /c:10 /f:RenderedXml /rd:true', 
                           capture_output=True, text=True, shell=True)
            if r.returncode != 0:
                continue
            events = re.findall(r'<Event[^>]*>.*?</Event>', r.stdout, re.DOTALL)
            for ex in events:
                try:
                    root = ET.fromstring(f'<?xml version="1.0"?>{ex}')
                    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    sys = root.find('.//e:System', ns)
                    if sys is None:
                        continue
                    eid = sys.find('e:EventID', ns)
                    lvl = sys.find('e:Level', ns)
                    tm = sys.find('e:TimeCreated', ns)
                    pr = sys.find('e:Provider', ns)
                    cn = sys.find('e:Channel', ns)
                    cp = sys.find('e:Computer', ns)
                    msg = root.find('.//e:Message', ns)
                    msg = msg.text if msg is not None else ''
                    un = 'SYSTEM'
                    dat = root.find('.//e:EventData', ns)
                    if dat:
                        for d in dat:
                            if d.get('Name') in ['TargetUserName', 'SubjectUserName'] and d.text:
                                if d.text not in ['SYSTEM', '-', '']:
                                    un = d.text
                                    break
                    lm = {'1': 'Critical', '2': 'Error', '3': 'Warning', '4': 'Info', '0': 'Info'}
                    log_data = {
                        'timestamp': tm.get('SystemTime') if tm else datetime.now().isoformat(),
                        'event_id': int(eid.text) if eid else 0,
                        'level': lm.get(lvl.text if lvl else '4', 'Info'),
                        'source': pr.get('Name') if pr else 'Unknown',
                        'channel': cn.text if cn else ch,
                        'computer': cp.text if cp else 'Unknown',
                        'username': un,
                        'message': msg[:500]
                    }
                    add_log(log_data)
                    total += 1
                    
                    # Emit real-time update
                    socketio.emit('new_log', log_data)
                    
                except:
                    continue
        except Exception as e:
            pass
    return total

def detect():
    alerts = []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Brute force
    c.execute("""SELECT username,computer,COUNT(*)as count FROM logs 
                 WHERE event_id=4625 AND processed=0 
                 AND timestamp>datetime('now','-1 minutes') 
                 GROUP BY username HAVING count>=3""")
    for row in c.fetchall():
        alert = {
            'severity': 'High',
            'title': f'Brute Force: {row["username"]}',
            'description': f'{row["count"]} failed logins',
            'rule_name': 'Brute Force',
            'username': row['username'],
            'event_id': 4625,
            'mitre_tactic': 'Credential Access'
        }
        aid = add_alert(alert)
        alert['id'] = aid
        alerts.append(alert)
    
    # Log cleared
    c.execute("SELECT username,computer FROM logs WHERE event_id=1102 AND processed=0")
    for row in c.fetchall():
        alert = {
            'severity': 'Critical',
            'title': 'LOG CLEARED',
            'description': f'By {row["username"]}',
            'rule_name': 'Anti-Forensics',
            'username': row['username'],
            'event_id': 1102,
            'mitre_tactic': 'Defense Evasion'
        }
        aid = add_alert(alert)
        alert['id'] = aid
        alerts.append(alert)
    
    # New service
    c.execute("SELECT message,computer FROM logs WHERE event_id=7045 AND processed=0")
    for row in c.fetchall():
        alert = {
            'severity': 'High',
            'title': 'New Service Installed',
            'description': row['message'][:100] if row['message'] else 'Unknown',
            'rule_name': 'Persistence',
            'username': None,
            'event_id': 7045,
            'mitre_tactic': 'Persistence'
        }
        aid = add_alert(alert)
        alert['id'] = aid
        alerts.append(alert)
    
    # Privileged access
    c.execute("""SELECT username FROM logs WHERE event_id=4672 AND processed=0 
                 AND timestamp>datetime('now','-1 minutes')""")
    for row in c.fetchall():
        alert = {
            'severity': 'Medium',
            'title': 'Privileged Access',
            'description': f'{row["username"]} used privileges',
            'rule_name': 'Privilege Escalation',
            'username': row['username'],
            'event_id': 4672,
            'mitre_tactic': 'Privilege Escalation'
        }
        aid = add_alert(alert)
        alert['id'] = aid
        alerts.append(alert)
    
    conn.close()
    mark_processed()
    
    # Emit real-time alerts
    for alert in alerts:
        socketio.emit('new_alert', alert)
    
    return len(alerts)

# HTML Templates
LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SIEM Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-box {
            background: #1f2937;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            width: 100%;
            max-width: 400px;
            border: 1px solid #374151;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #3b82f6;
            font-size: 28px;
        }
        .logo p {
            color: #6b7280;
            margin-top: 8px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #9ca3af;
            margin-bottom: 8px;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: #111827;
            border: 1px solid #374151;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #3b82f6;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4);
        }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #ef4444;
            color: #fca5a5;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>🛡️ Windows SIEM</h1>
            <p>Security Operations Center</p>
        </div>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Windows SIEM - Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0a0e1a;
            color: #fff;
            padding: 20px;
        }
        .header {
            background: #1f2937;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #374151;
        }
        .header h1 { color: #3b82f6; }
        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .role-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .role-admin { background: #ef4444; }
        .role-analyst { background: #3b82f6; }
        .logout-btn {
            background: #374151;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1f2937;
            padding: 24px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #374151;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #3b82f6;
        }
        .stat-value.danger { color: #ef4444; }
        .stat-label {
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
            margin-top: 8px;
        }
        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .chart-card {
            background: #1f2937;
            padding: 20px;
            border-radius: 12px;
            border: 1px solid #374151;
        }
        .chart-card h3 {
            margin-bottom: 16px;
            color: #9ca3af;
            font-size: 14px;
            text-transform: uppercase;
        }
        .panel {
            background: #1f2937;
            border-radius: 12px;
            border: 1px solid #374151;
            margin-bottom: 20px;
        }
        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid #374151;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-header h2 { font-size: 16px; }
        .btn {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
        }
        .btn:hover { background: #2563eb; }
        .btn-secondary { background: #374151; }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .alert-item {
            padding: 16px 20px;
            border-bottom: 1px solid #374151;
            border-left: 4px solid #f59e0b;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .alert-item.critical { border-left-color: #dc2626; background: rgba(220, 38, 38, 0.1); }
        .alert-item.high { border-left-color: #ea580c; }
        .alert-item.medium { border-left-color: #f59e0b; }
        .alert-title { font-weight: 600; margin-bottom: 4px; }
        .alert-desc { font-size: 13px; color: #9ca3af; }
        .alert-meta {
            font-size: 11px;
            color: #6b7280;
            margin-top: 8px;
            display: flex;
            justify-content: space-between;
        }
        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { 
            background: #dc2626; 
            color: white;
            box-shadow: 0 0 8px rgba(220, 38, 38, 0.4);
        }
        .badge-high { 
            background: #ea580c; 
            color: white;
        }
        .badge-medium { 
            background: #f59e0b; 
            color: #000;
        }
        .badge-low { 
            background: #10b981; 
            color: white;
        }
        .badge-info { 
            background: #3b82f6; 
            color: white;
        }
        .badge-error {
            background: #ef4444;
            color: white;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th {
            background: #111827;
            padding: 12px;
            text-align: left;
            position: sticky;
            top: 0;
            color: #6b7280;
            font-weight: 500;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #374151;
        }
        tr:hover { background: rgba(59,130,246,0.05); }
        .logs-container {
            max-height: 400px;
            overflow: auto;
        }
        .real-time-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            color: #10b981;
        }
        .pulse {
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        .empty { text-align: center; padding: 40px; color: #6b7280; }
        input[type="text"] {
            background: #111827;
            border: 1px solid #374151;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            width: 250px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Windows SIEM - Dashboard</h1>
        <div class="user-info">
            <span>👤 {{ username }}</span>
            <span class="role-badge role-{{ role }}">{{ role }}</span>
            <div class="real-time-indicator">
                <div class="pulse"></div>
                <span>LIVE (1s)</span>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value" id="stat-logs">0</div>
            <div class="stat-label">Total Events</div>
        </div>
        <div class="stat-card">
            <div class="stat-value danger" id="stat-active">0</div>
            <div class="stat-label">Active Alerts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="stat-total">0</div>
            <div class="stat-label">Total Alerts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="stat-last">--</div>
            <div class="stat-label">Last Event</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="chart-card">
            <h3>📊 Events Per Hour (Last 24h)</h3>
            <canvas id="hourlyChart"></canvas>
        </div>
        <div class="chart-card">
            <h3>🎯 Alert Severity Distribution</h3>
            <canvas id="severityChart"></canvas>
        </div>
    </div>

    <div class="panel">
        <div class="panel-header">
            <h2>🚨 Security Alerts</h2>
            <div>
                {% if is_admin %}
                <button class="btn btn-secondary" onclick="ackAll()" id="btn-ack-all">Acknowledge All</button>
                {% endif %}
                <button class="btn" onclick="manualRefresh()">Refresh Now</button>
            </div>
        </div>
        <div id="alerts-container"></div>
    </div>

    <div class="panel">
        <div class="panel-header">
            <h2>📋 Recent Event Logs</h2>
            <input type="text" id="search" placeholder="Search logs..." onkeyup="filterLogs()">
        </div>
        <div class="logs-container">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Level</th>
                        <th>Event ID</th>
                        <th>Source</th>
                        <th>User</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody id="logs-body"></tbody>
            </table>
        </div>
    </div>

    <script>
        const socket = io();
        const isAdmin = {{ is_admin|tojson }};
        let allLogs = [];
        let hourlyChart, severityChart;

        function getBadgeClass(level) {
            const l = level.toLowerCase();
            if (l === 'critical') return 'badge-critical';
            if (l === 'high' || l === 'error') return 'badge-high';
            if (l === 'warning' || l === 'medium') return 'badge-medium';
            if (l === 'low') return 'badge-low';
            return 'badge-info';
        }

        function initCharts() {
            const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
            hourlyChart = new Chart(hourlyCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Events',
                        data: [],
                        backgroundColor: '#3b82f6',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#374151' }, ticks: { color: '#9ca3af' } },
                        x: { grid: { display: false }, ticks: { color: '#9ca3af' } }
                    }
                }
            });

            const severityCtx = document.getElementById('severityChart').getContext('2d');
            severityChart = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#3b82f6']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af' } }
                    }
                }
            });
        }

        async function loadData() {
            try {
                const [stats, alerts, logs] = await Promise.all([
                    fetch('/api/stats').then(r => r.json()),
                    fetch('/api/alerts').then(r => r.json()),
                    fetch('/api/logs').then(r => r.json())
                ]);

                document.getElementById('stat-logs').textContent = stats.total_logs.toLocaleString();
                document.getElementById('stat-active').textContent = stats.active_alerts;
                document.getElementById('stat-total').textContent = stats.total_alerts;
                document.getElementById('stat-last').textContent = new Date().toLocaleTimeString();

                if (stats.hourly) {
                    hourlyChart.data.labels = stats.hourly.map(h => h.hour + ':00');
                    hourlyChart.data.datasets[0].data = stats.hourly.map(h => h.count);
                    hourlyChart.update();
                }

                if (stats.severity) {
                    severityChart.data.labels = stats.severity.map(s => s.severity);
                    severityChart.data.datasets[0].data = stats.severity.map(s => s.count);
                    severityChart.update();
                }

                renderAlerts(alerts);
                allLogs = logs;
                renderLogs(logs);
            } catch (e) {
                console.error('Load error:', e);
            }
        }

        function renderAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            if (!alerts.length) {
                container.innerHTML = '<div class="empty">No active alerts</div>';
                return;
            }

            container.innerHTML = alerts.map(a => `
                <div class="alert-item ${a.severity.toLowerCase()}">
                    <div class="alert-title">${a.title}</div>
                    <div class="alert-desc">${a.description}</div>
                    <div class="alert-meta">
                        <span>
                            <span class="badge ${getBadgeClass(a.severity)}">${a.severity}</span>
                            ${a.rule_name} | ${a.mitre_tactic || 'N/A'} | 
                            ${new Date(a.timestamp).toLocaleString()}
                        </span>
                        ${isAdmin ? `<button class="btn btn-secondary" onclick="ackAlert(${a.id})">Acknowledge</button>` : ''}
                    </div>
                </div>
            `).join('');
        }

        function renderLogs(logs) {
            const term = document.getElementById('search').value.toLowerCase();
            const filtered = term ? logs.filter(l => 
                (l.message && l.message.toLowerCase().includes(term)) ||
                l.source.toLowerCase().includes(term) ||
                l.username.toLowerCase().includes(term)
            ) : logs;

            document.getElementById('logs-body').innerHTML = filtered.map(l => `
                <tr>
                    <td>${new Date(l.timestamp).toLocaleTimeString()}</td>
                    <td><span class="badge ${getBadgeClass(l.level)}">${l.level}</span></td>
                    <td>${l.event_id}</td>
                    <td>${l.source}</td>
                    <td>${l.username}</td>
                    <td>${l.message ? l.message.substring(0, 60) + '...' : '-'}</td>
                </tr>
            `).join('');
        }

        function filterLogs() {
            renderLogs(allLogs);
        }

        async function ackAlert(id) {
            await fetch(`/api/alerts/${id}/ack`, { method: 'POST' });
            loadData();
        }

        async function ackAll() {
            if (!confirm('Acknowledge all alerts?')) return;
            await fetch('/api/alerts/ack-all', { method: 'POST' });
            loadData();
        }

        async function manualRefresh() {
            await fetch('/api/collect', { method: 'POST' });
            await fetch('/api/detect', { method: 'POST' });
            loadData();
        }

        socket.on('new_log', (log) => {
            allLogs.unshift(log);
            if (allLogs.length > 100) allLogs.pop();
            renderLogs(allLogs);
            document.getElementById('stat-logs').textContent = 
                parseInt(document.getElementById('stat-logs').textContent) + 1;
            document.getElementById('stat-last').textContent = new Date().toLocaleTimeString();
        });

        socket.on('new_alert', (alert) => {
            loadData();
        });

        socket.on('stats_update', (stats) => {
            document.getElementById('stat-active').textContent = stats.active_alerts;
        });

        initCharts();
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>
'''

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_password(username, password):
            user = get_user_by_username(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_HTML, error='Invalid credentials')
    
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, 
                                  username=current_user.username,
                                  role=current_user.role,
                                  is_admin=current_user.is_admin())

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_stats())

@app.route('/api/logs')
@login_required
def api_logs():
    return jsonify(get_logs())

@app.route('/api/alerts')
@login_required
def api_alerts():
    return jsonify(get_alerts(acknowledged=False))

@app.route('/api/alerts/<int:aid>/ack', methods=['POST'])
@admin_required
def api_ack(aid):
    ack_alert(aid)
    socketio.emit('stats_update', get_stats())
    return jsonify({'ok': True})

@app.route('/api/alerts/ack-all', methods=['POST'])
@admin_required
def api_ack_all():
    ack_all()
    socketio.emit('stats_update', get_stats())
    return jsonify({'ok': True})

@app.route('/api/collect', methods=['POST'])
@login_required
def api_collect():
    count = collect()
    return jsonify({'collected': count})

@app.route('/api/detect', methods=['POST'])
@login_required
def api_detect():
    count = detect()
    return jsonify({'alerts': count})

# Background task - RUNS EVERY 1 SECOND
def bg_task():
    while True:
        try:
            collect()
            detect()
            socketio.emit('stats_update', get_stats())
        except Exception as e:
            print(f"BG error: {e}")
        socketio.sleep(1)  # CHANGED FROM 30 TO 1 SECOND

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════╗
║         Windows SIEM - Real-Time Edition                 ║
╠══════════════════════════════════════════════════════════╣
║  Collection Interval: EVERY 1 SECOND                    ║
║  Features:                                               ║
║  ✓ User Authentication (Admin/Analyst roles)            ║
║  ✓ Real-time WebSocket updates (1s)                     ║
║  ✓ Charts & Visualizations                              ║
║  ✓ Color-coded severity levels                          ║
╠══════════════════════════════════════════════════════════╣
║  Default Login:                                          ║
║  Admin:   username=admin     password=admin123          ║
║  Analyst: username=analyst   password=analyst123      ║
╚══════════════════════════════════════════════════════════╝
""")
    init_db()
    
    # Initial collection
    collect()
    detect()
    
    # Start background task
    socketio.start_background_task(bg_task)
    
    print("\n🚀 Starting server at http://localhost:5000")
    print("🔐 Login page: http://localhost:5000/login")
    print("⚡ Real-time updates: EVERY 1 SECOND\n")
    
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)