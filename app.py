from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import tensorflow as tf
from tensorflow.keras.models import load_model
import numpy as np
import joblib
import time
import os
from playwright.sync_api import sync_playwright
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import urllib.request
import urllib.parse
import json
import math
import re
import base64

app = Flask(__name__, template_folder='templates', static_folder='templates', static_url_path='')
CORS(app)

# --- Updated Model Loading ---
print("Loading Best Phishing Model and Scaler...")
try:
    # Updated filenames as requested
    model = load_model("best_phishing_model.h5")
    scaler = joblib.load("scaler.pkl")
    print("Model and Scaler loaded successfully!")
except Exception as e:
    print(f"Error loading assets: {e}")
    model = None
    scaler = None

# --- New Feature Extraction Logic ---
def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = text.count(x) / len(text)
        entropy += -p_x * math.log2(p_x)
    return entropy

def extract_features(url):
    u = str(url).lower()
    if not u.startswith("http"):
        u = "http://" + u

    parsed = urlparse(u)
    domain = parsed.netloc

    # List of 14 features as requested
    features = [
        len(u),
        len(domain),
        calculate_entropy(u),
        domain.count('.'),
        sum(c.isdigit() for c in u),
        len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]', u)),
        u.count('/'),
        1 if u.startswith("https") else 0,
        calculate_entropy(domain),
        1 if "login" in u or "secure" in u or "bank" in u else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        u.count('-'),
        len(parsed.query),
        1 if "@" in u else 0
    ]
    return np.array(features).reshape(1, -1)

# --- Helper Functions (Kept as is) ---

def take_screenshot(url):
    """Take screenshot and return as base64 data"""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_extra_http_headers({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            screenshot_bytes = page.screenshot(full_page=False)
            browser.close()
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            return f"data:image/png;base64,{screenshot_b64}"
    except Exception as e:
        print(f"Screenshot failed for {url}: {e}")
        return None

def check_url_safety(url_string):
    if not scaler or not model:
        return {"status": "Unable to Process", "message": "Model or Scaler not loaded", "color": "orange"}
    
    try:
        # Use the new extract_features function
        features_array = extract_features(url_string)
        
        # Scale features
        scaled_features = scaler.transform(features_array)
        
        # Reshape for CNN/LSTM (Batch, Timesteps, Features) 
        # Assuming your model expects (1, 14, 1)
        cnn_ready_features = np.expand_dims(scaled_features, axis=2)
        
        # Predict
        prob = model.predict(cnn_ready_features, verbose=0)[0][0]
        
        if prob > 0.5:
            return {"status": "Phishing", "message": f"Danger! {prob*100:.2f}% Phishing Probability.", "color": "red"}
        else:
            return {"status": "Safe", "message": f"Looks good! {(1-prob)*100:.2f}% Safe Probability.", "color": "green"}
            
    except Exception as e:
        print(f"Prediction error: {e}")
        return {"status": "Error", "message": "Failed to analyze the URL parameters.", "color": "red"}

def extract_brand_and_tld(url_string):
    try:
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        if ':' in domain: domain = domain.split(':')[0]
        domain_parts = domain.split('.')
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else 'unknown'
        brand = domain_parts[-2].lower() if len(domain_parts) >= 2 else domain.lower()
        return {"brand": brand, "tld": tld, "full_domain": domain}
    except:
        return {"brand": "unknown", "tld": "unknown", "full_domain": url_string}

def get_host_from_url(url_string):
    try:
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        return domain.split(':')[0] if ':' in domain else domain
    except:
        return "Unknown"

def get_ip_address(url_string):
    try:
        domain = get_host_from_url(url_string)
        return socket.gethostbyname(domain)
    except:
        return "Unknown"

def get_hosting_provider(url_string):
    try:
        domain = get_host_from_url(url_string).lower()
        providers = {
            'google': "Google", 'azure': "Microsoft", 'aws': "Amazon Web Services",
            'cloudflare': "Cloudflare", 'github': "GitHub", 'facebook': "Meta",
            'apple': "Apple", 'netflix': "Netflix", 'twitter': "X Corp", 'vit.ac.in': "VIT"
        }
        for key, value in providers.items():
            if key in domain: return value
        return domain.split('.')[-2].capitalize() if '.' in domain else "Unknown Provider"
    except:
        return "Unknown Provider"

def get_current_date():
    now = datetime.now()
    day = now.day
    suffix = 'th' if 10 <= day <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
    return now.strftime(f"%B {day}{suffix} %Y %I:%M:%S %p")

def get_ssl_certificate_info(url_string):
    try:
        domain = get_host_from_url(url_string)
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown Issuer')
                return {"issuer": issuer, "domain": domain, "verified": True}
    except:
        return {"issuer": "Certificate Not Available", "domain": get_host_from_url(url_string), "verified": False}

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/finial')
def finial():
    return render_template('finial.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        if not data: return jsonify({"error": "No JSON data provided"}), 400
            
        user_url = data.get('url', '').strip()
        if not user_url: return jsonify({"error": "No URL provided"}), 400
        
        result = check_url_safety(user_url)
        result["screenshot"] = take_screenshot(user_url)
        result["certificate"] = get_ssl_certificate_info(user_url)
        
        brand_info = extract_brand_and_tld(user_url)
        result["brand"] = brand_info["brand"]
        result["tld"] = brand_info["tld"]
        result["host"] = get_host_from_url(user_url)
        result["ip_address"] = get_ip_address(user_url)
        result["hosting_provider"] = get_hosting_provider(user_url)
        result["detection_date"] = get_current_date()
        
        if result["status"] == "Phishing":
            result["warning"] = "This URL has been flagged as potentially malicious."
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
