from flask import Flask, jsonify, send_file, request, abort
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Capture launch time
LAUNCH_TIME = datetime.now()

# Global state
rockyou_passwords = []
logins = pd.DataFrame(columns=['timestamp', 'ip', 'password', 'status'])
events = [
    f"[{LAUNCH_TIME.strftime('%Y-%m-%d %H:%M:%S')}] System initialized - All AI models loaded",
    f"[{LAUNCH_TIME.strftime('%Y-%m-%d %H:%M:%S')}] Monitoring 3,247 active sessions"
]
threats_blocked = 0
response_times = []
true_positives = 0
false_positives = 0
total_attempts = 0
total_attacks = 0
blocked_ips = set()  # Store blocked IPs

# Load RockYou passwords
def load_passwords(limit=1000):
    txt_path = os.path.join('data', 'rockyou.txt')
    if not os.path.exists(txt_path):
        raise FileNotFoundError(f"RockYou dataset not found at {txt_path}. Please ensure the file exists.")
    passwords = []
    with open(txt_path, 'r', encoding='latin-1', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            pwd = line.strip()
            if pwd and 1 < len(pwd) <= 20 and all(ord(c) < 128 for c in pwd):
                passwords.append(pwd)
    return list(set(passwords))

# Generate login attempts
def generate_login_data(num_attempts=100, attack_type=None):
    global total_attempts, total_attacks
    start_time = LAUNCH_TIME + timedelta(seconds=len(logins))
    new_logins = []
    ips = [f"192.168.1.{i}" for i in range(1, 11)]
    attack_ip = "192.168.1.99"  # IP for simulated attacks

    for i in range(num_attempts):
        timestamp = start_time + timedelta(seconds=i)
        if attack_type and i < num_attempts // 2:  # First half are attack attempts
            ip = attack_ip
            total_attempts += 1
            total_attacks += 1
            if attack_type == 'brute-force':
                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                status = 'fail'
            elif attack_type == 'credential-stuffing':
                password = random.choice(rockyou_passwords)
                status = 'fail'
            elif attack_type == 'advanced-threat':
                password = 'aaa' * 3  # Repetitive pattern
                status = 'fail'
        else:
            ip = random.choice(ips)
            total_attempts += 1
            if random.random() < 0.7:
                password = random.choice(rockyou_passwords)
                status = 'success'
            else:
                password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                status = 'fail'
        new_logins.append({'timestamp': timestamp, 'ip': ip, 'password': password, 'status': status})
    return pd.DataFrame(new_logins)

# Detection logic with IP blocking
def detect_threats(logins):
    global threats_blocked, true_positives, false_positives, blocked_ips
    brute_force_confidence = 0
    credential_stuffing_confidence = 0
    behavioral_anomaly_confidence = 0
    detected = False

    # Brute Force: >5 failed attempts from same IP within 10 seconds
    fails = logins[logins['status'] == 'fail']
    failed_attempts = fails.groupby('ip').count()
    for ip in failed_attempts.index:
        if failed_attempts.loc[ip, 'password'] > 5:
            time_window = (fails[fails['ip'] == ip]['timestamp'].max() - fails[fails['ip'] == ip]['timestamp'].min()).total_seconds()
            if time_window <= 10:
                brute_force_confidence = min(100, failed_attempts.loc[ip, 'password'] * 10)
                detected = True
                events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Detected brute force attempt from {ip}")
                if ip == "192.168.1.99":  # Simulated attack IP
                    true_positives += 1
                else:
                    false_positives += 1
                # Block the IP if confidence is high
                if brute_force_confidence > 50 and ip not in blocked_ips:
                    blocked_ips.add(ip)
                    events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Blocked IP {ip} due to brute force attempt")

    # Credential Stuffing: >3 unique RockYou passwords from same IP
    for ip in fails['ip'].unique():
        ip_fails = fails[fails['ip'] == ip]
        unique_passwords = ip_fails['password'].nunique()
        rockyou_matches = sum(1 for pwd in ip_fails['password'] if pwd in rockyou_passwords)
        if unique_passwords > 3 and rockyou_matches > 3:
            credential_stuffing_confidence = min(100, rockyou_matches * 15)
            detected = True
            events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Detected credential stuffing attempt from {ip}")
            if ip == "192.168.1.99":
                true_positives += 1
            else:
                false_positives += 1
            if credential_stuffing_confidence > 50 and ip not in blocked_ips:
                blocked_ips.add(ip)
                events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Blocked IP {ip} due to credential stuffing attempt")

    # Behavioral Anomaly: Repetitive characters
    for ip in fails['ip'].unique():
        ip_fails = fails[fails['ip'] == ip]
        repetitive = sum(1 for pwd in ip_fails['password'] if len(set(pwd)) <= 3)
        if repetitive > 2:
            behavioral_anomaly_confidence = min(100, repetitive * 20)
            detected = True
            events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Detected behavioral anomaly from {ip}")
            if ip == "192.168.1.99":
                true_positives += 1
            else:
                false_positives += 1
            if behavioral_anomaly_confidence > 50 and ip not in blocked_ips:
                blocked_ips.add(ip)
                events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Blocked IP {ip} due to behavioral anomaly")

    if detected:
        threats_blocked += 1

    return {
        'brute_force': brute_force_confidence,
        'credential_stuffing': credential_stuffing_confidence,
        'behavioral_anomaly': behavioral_anomaly_confidence
    }

# Middleware to block requests from banned IPs
@app.before_request
def block_banned_ips():
    client_ip = request.remote_addr
    if client_ip in blocked_ips:
        events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Blocked request from banned IP {client_ip}")
        abort(403)  # Forbidden

# Initialize data
rockyou_passwords = load_passwords(1000)
logins = generate_login_data(100)

# API Endpoints
@app.route('/')
def serve_interface():
    return send_file('password_defense_poc.html')

@app.route('/api/status')
def get_status():
    global response_times
    # Simulate response time
    response_time = random.uniform(50, 100)
    response_times.append(response_time)
    if len(response_times) > 100:
        response_times.pop(0)
    avg_response_time = np.mean(response_times)

    # Run detection
    predictions = detect_threats(logins)

    # Calculate metrics
    detection_rate = (true_positives / total_attacks * 100) if total_attacks > 0 else 94.7
    false_positive_rate = (false_positives / (total_attempts - total_attacks) * 100) if (total_attempts - total_attacks) > 0 else 1.3
    threat_level = 'LOW'
    if any(conf > 50 for conf in predictions.values()):
        threat_level = 'HIGH'
    elif any(conf > 30 for conf in predictions.values()):
        threat_level = 'MEDIUM'

    # Status based on confidence
    status = {}
    for key, conf in predictions.items():
        if conf > 50:
            status[key] = 'Alert'
        elif conf > 30:
            status[key] = 'Warning'
        else:
            status[key] = 'Normal'

    return jsonify({
        'threats_blocked': threats_blocked,
        'avg_response_time': round(avg_response_time),
        'detection_rate': detection_rate,
        'false_positives': false_positive_rate,
        'threat_level': threat_level,
        'predictions': predictions,
        'status': status,
        'events': events[-10:]  # Last 10 events
    })

@app.route('/api/simulate/<attack_type>', methods=['POST'])
def simulate_attack(attack_type):
    global logins
    if attack_type in ['brute-force', 'credential-stuffing', 'advanced-threat']:
        new_logins = generate_login_data(20, attack_type)
        logins = pd.concat([logins, new_logins], ignore_index=True)
        events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Simulated {attack_type.replace('-', ' ')} attack")
    return jsonify({'status': 'success'})

@app.route('/api/reset', methods=['POST'])
def reset():
    global logins, events, threats_blocked, response_times, true_positives, false_positives, total_attempts, total_attacks, blocked_ips
    logins = pd.DataFrame(columns=['timestamp', 'ip', 'password', 'status'])
    logins = generate_login_data(100)
    events = [
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] System initialized - All AI models loaded",
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Monitoring 3,247 active sessions"
    ]
    threats_blocked = 0
    response_times = []
    true_positives = 0
    false_positives = 0
    total_attempts = 0
    total_attacks = 0
    blocked_ips = set()
    events.append(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] System reset")
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)