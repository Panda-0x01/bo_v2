from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from datetime import datetime, timedelta
import random
import time
import requests
from collections import defaultdict
import threading
import json

app = Flask(__name__)
CORS(app)

# In-memory storage
logs = []
alerts = []
request_counts = defaultdict(list)
demo_api_active = False
real_api_monitor_active = False
real_api_url = None

# Simulated data
SAMPLE_IPS = [
    "192.168.1.100", "10.0.0.5", "172.16.0.10", "203.0.113.45",
    "198.51.100.23", "192.0.2.150", "192.168.1.101", "10.0.0.6"
]

ENDPOINTS = [
    "/api/users", "/api/products", "/api/orders", 
    "/api/login", "/api/data", "/api/search"
]

METHODS = ["GET", "POST", "PUT", "DELETE"]

# Abuse detection thresholds
RATE_LIMIT_THRESHOLD = 10  # requests per minute
SUSPICIOUS_IP_THRESHOLD = 15  # total requests from single IP

def generate_fake_request():
    """Generate a fake API request"""
    return {
        "timestamp": datetime.now().isoformat(),
        "ip": random.choice(SAMPLE_IPS),
        "endpoint": random.choice(ENDPOINTS),
        "method": random.choice(METHODS),
        "status": random.choice([200, 200, 200, 400, 401, 403, 404, 500]),
        "response_time": round(random.uniform(0.05, 2.0), 3),
        "user_agent": random.choice([
            "Mozilla/5.0", "PostmanRuntime/7.26.8", 
            "Python/requests", "curl/7.64.1"
        ])
    }

def detect_abuse():
    """Detect potential API abuse patterns"""
    global alerts
    alerts = []
    
    # Count requests per IP in last minute
    one_minute_ago = datetime.now() - timedelta(minutes=1)
    recent_requests = defaultdict(int)
    ip_endpoints = defaultdict(set)
    
    for log in logs[-100:]:  # Check last 100 logs
        log_time = datetime.fromisoformat(log["timestamp"])
        if log_time > one_minute_ago:
            recent_requests[log["ip"]] += 1
            ip_endpoints[log["ip"]].add(log["endpoint"])
    
    # Rate limit violations
    for ip, count in recent_requests.items():
        if count > RATE_LIMIT_THRESHOLD:
            alerts.append({
                "type": "RATE_LIMIT_VIOLATION",
                "severity": "HIGH",
                "ip": ip,
                "message": f"IP {ip} exceeded rate limit with {count} requests/min",
                "timestamp": datetime.now().isoformat()
            })
    
    # Suspicious IP patterns
    total_requests_per_ip = defaultdict(int)
    for log in logs[-200:]:
        total_requests_per_ip[log["ip"]] += 1
    
    for ip, count in total_requests_per_ip.items():
        if count > SUSPICIOUS_IP_THRESHOLD:
            alerts.append({
                "type": "SUSPICIOUS_ACTIVITY",
                "severity": "MEDIUM",
                "ip": ip,
                "message": f"IP {ip} made {count} requests recently",
                "timestamp": datetime.now().isoformat()
            })
    
    # Failed authentication attempts
    failed_auth = defaultdict(int)
    for log in logs[-100:]:
        if log["endpoint"] == "/api/login" and log["status"] in [401, 403]:
            failed_auth[log["ip"]] += 1
    
    for ip, count in failed_auth.items():
        if count > 5:
            alerts.append({
                "type": "BRUTE_FORCE_ATTEMPT",
                "severity": "CRITICAL",
                "ip": ip,
                "message": f"Possible brute force: {count} failed login attempts from {ip}",
                "timestamp": datetime.now().isoformat()
            })
    
    return alerts

@app.route('/')
def index():
    """Serve the dashboard HTML"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/simulate', methods=['POST'])
def simulate():
    """Generate simulated API requests"""
    data = request.json
    num_requests = data.get('count', 20)
    
    # Generate requests with some abusive patterns
    for i in range(num_requests):
        req = generate_fake_request()
        
        # Occasionally create abuse patterns
        if random.random() > 0.7:  # 30% chance
            req["ip"] = SAMPLE_IPS[0]  # Same IP
        
        if random.random() > 0.8:  # 20% chance
            req["endpoint"] = "/api/login"
            req["status"] = 401  # Failed login
        
        logs.append(req)
    
    # Keep only last 500 logs
    if len(logs) > 500:
        logs[:] = logs[-500:]
    
    detect_abuse()
    
    return jsonify({
        "success": True,
        "generated": num_requests,
        "total_logs": len(logs)
    })

@app.route('/detect', methods=['POST'])
def detect():
    """Run abuse detection"""
    detected_alerts = detect_abuse()
    return jsonify({
        "success": True,
        "alerts_found": len(detected_alerts),
        "alerts": detected_alerts
    })

@app.route('/get_logs', methods=['GET'])
def get_logs():
    """Return recent logs"""
    limit = int(request.args.get('limit', 50))
    return jsonify(logs[-limit:])

@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    """Return current alerts"""
    return jsonify(alerts)

@app.route('/demo-api', methods=['GET', 'POST'])
def demo_api():
    """Demo API endpoint for testing"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": request.remote_addr or random.choice(SAMPLE_IPS),
        "endpoint": "/demo-api",
        "method": request.method,
        "status": 200,
        "response_time": round(random.uniform(0.1, 0.5), 3),
        "user_agent": request.headers.get('User-Agent', 'Unknown')
    }
    logs.append(log_entry)
    
    return jsonify({
        "message": "Demo API response",
        "timestamp": datetime.now().isoformat(),
        "data": {"id": random.randint(1, 1000)}
    })

def generate_demo_traffic():
    """Background thread to generate demo API traffic"""
    global demo_api_active
    while demo_api_active:
        try:
            # Simulate internal API call
            req = generate_fake_request()
            req["endpoint"] = "/demo-api"
            logs.append(req)
            time.sleep(random.uniform(0.5, 2.0))
        except Exception as e:
            print(f"Error generating demo traffic: {e}")
            break

@app.route('/toggle_demo_api', methods=['POST'])
def toggle_demo_api():
    """Start or stop demo API traffic generation"""
    global demo_api_active
    data = request.json
    action = data.get('action', 'start')
    
    if action == 'start' and not demo_api_active:
        demo_api_active = True
        thread = threading.Thread(target=generate_demo_traffic, daemon=True)
        thread.start()
        return jsonify({"success": True, "status": "started"})
    elif action == 'stop':
        demo_api_active = False
        return jsonify({"success": True, "status": "stopped"})
    
    return jsonify({"success": False, "message": "Already running"})

def monitor_real_api():
    """Background thread to monitor real API"""
    global real_api_monitor_active, real_api_url
    while real_api_monitor_active and real_api_url:
        try:
            start_time = time.time()
            response = requests.get(real_api_url, timeout=5)
            response_time = time.time() - start_time
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "ip": "MONITOR",
                "endpoint": real_api_url,
                "method": "GET",
                "status": response.status_code,
                "response_time": round(response_time, 3),
                "user_agent": "API Monitor"
            }
            logs.append(log_entry)
            time.sleep(5)  # Check every 5 seconds
        except Exception as e:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "ip": "MONITOR",
                "endpoint": real_api_url,
                "method": "GET",
                "status": 0,
                "response_time": 0,
                "user_agent": f"API Monitor - Error: {str(e)}"
            }
            logs.append(log_entry)
            time.sleep(10)

@app.route('/monitor_real_api', methods=['POST'])
def monitor_real():
    """Start monitoring a real API"""
    global real_api_monitor_active, real_api_url
    data = request.json
    action = data.get('action', 'start')
    
    if action == 'start':
        url = data.get('url', '')
        if url:
            real_api_url = url
            real_api_monitor_active = True
            thread = threading.Thread(target=monitor_real_api, daemon=True)
            thread.start()
            return jsonify({"success": True, "status": "monitoring", "url": url})
    elif action == 'stop':
        real_api_monitor_active = False
        real_api_url = None
        return jsonify({"success": True, "status": "stopped"})
    
    return jsonify({"success": False, "message": "Invalid request"})

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    """Clear all logs and alerts"""
    global logs, alerts
    logs = []
    alerts = []
    return jsonify({"success": True, "message": "Logs cleared"})

@app.route('/stats', methods=['GET'])
def stats():
    """Get dashboard statistics"""
    total_requests = len(logs)
    total_alerts = len(alerts)
    
    # Count by status
    status_counts = defaultdict(int)
    for log in logs[-100:]:
        status_counts[log["status"]] += 1
    
    # Count by endpoint
    endpoint_counts = defaultdict(int)
    for log in logs[-100:]:
        endpoint_counts[log["endpoint"]] += 1
    
    return jsonify({
        "total_requests": total_requests,
        "total_alerts": total_alerts,
        "demo_api_active": demo_api_active,
        "real_api_active": real_api_monitor_active,
        "status_counts": dict(status_counts),
        "top_endpoints": dict(sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    })

HTML_TEMPLATE = open('dashboard.html', 'r').read() if __name__ != '__main__' else ''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)