from flask import Flask, render_template, request, jsonify
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

app = Flask(__name__, template_folder='templates', static_folder='templates', static_url_path='')


print("Loading Tabular CNN+Bi-LSTM Model, Scaler, and TLD Encoder...")
try:
    model = load_model("tabular_cnn_lstm_model.h5")
    scaler = joblib.load("tabular_scaler.pkl")
    tld_encoder = joblib.load("tabular_tld_encoder.pkl")
    print("Model, Scaler, and TLD Encoder loaded successfully!")
except Exception as e:
    print(f"Error loading assets: {e}")
    model = None
    scaler = None
    tld_encoder = None

def calculate_entropy(text):
    """Calculate Shannon entropy for a text string"""
    if not text or not isinstance(text, str):
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log2(p_x)
    return entropy

def take_screenshot(url):
    """Take screenshot and return as base64 data instead of saving to file"""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Set user agent to avoid detection
            page.set_extra_http_headers({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # Navigate with longer timeout for suspicious sites
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            
            # Wait a bit for dynamic content
            page.wait_for_timeout(2000)
            
            # Take screenshot as bytes
            screenshot_bytes = page.screenshot(full_page=False)
            browser.close()
            
            # Convert to base64
            import base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            return f"data:image/png;base64,{screenshot_b64}"
            
    except Exception as e:
        print(f"Screenshot failed for {url}: {e}")
        # Return a placeholder for failed screenshots
        return None

def check_url_safety(url_string):
    if not scaler or not model or not tld_encoder:
        return {"status": "Unable to Process", "message": "Model or Scaler or TLD Encoder not loaded", "color": "orange"}
    
    try:
        # Extract the 10 mathematical features
        u = str(url_string).lower()
        https_flag = 1 if u.startswith('https') else 0
        if not u.startswith('http'): 
            u = 'http://' + u
            
        parsed = urlparse(u)
        domain = parsed.netloc
        
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else ''
        
        try:
            encoded_tld = tld_encoder.transform([tld])[0]
        except ValueError:
            encoded_tld = 0 # Fallback for unknown TLDs
            
        features = [
            len(u),
            len(domain),
            encoded_tld,
            calculate_entropy(u),
            domain.count('.'),
            sum(c.isdigit() for c in u),
            len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]', u)),
            u.count('/'),
            https_flag,
            calculate_entropy(domain)
        ]
        
        # Scale and reshape for the CNN (Batch, Timesteps, Features) -> (1, 10, 1)
        features_array = np.array(features).reshape(1, -1)
        scaled_features = scaler.transform(features_array)
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
    """Extract brand name and TLD from URL"""
    try:
        # Parse URL
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Extract TLD and brand
        domain_parts = domain.split('.')
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else 'unknown'
        
        # Extract brand name (usually the part before TLD)
        if len(domain_parts) >= 2:
            brand = domain_parts[-2].lower()
        else:
            brand = domain.lower()
        
        return {
            "brand": brand,
            "tld": tld,
            "full_domain": domain
        }
    except Exception as e:
        print(f"Error extracting brand and TLD: {e}")
        return {
            "brand": "unknown",
            "tld": "unknown",
            "full_domain": url_string
        }

def get_host_from_url(url_string):
    """Extract hostname and IP address from URL"""
    try:
        # Parse URL
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain  # Return hostname/domain
    except Exception as e:
        print(f"Error getting host from URL: {e}")
        return "Unknown"

def get_ip_address(url_string):
    """Resolve IP address from URL domain"""
    try:
        # Parse URL
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Resolve IP address
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        print(f"Error resolving IP address: {e}")
        return "Unknown"

def get_hosting_provider(url_string):
    """Get hosting provider information for the domain"""
    try:
        # Parse URL to get domain
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        domain_lower = domain.lower()
        
        # Determine hosting provider based on domain
        if 'google' in domain_lower or 'googleapis' in domain_lower:
            return "Google"
        elif 'microsoft' in domain_lower or 'azure' in domain_lower:
            return "Microsoft"
        elif 'amazon' in domain_lower or 'aws' in domain_lower:
            return "Amazon Web Services"
        elif 'cloudflare' in domain_lower:
            return "Cloudflare"
        elif 'github' in domain_lower:
            return "GitHub"
        elif 'facebook' in domain_lower or 'meta' in domain_lower:
            return "Meta (Facebook)"
        elif 'apple' in domain_lower:
            return "Apple"
        elif 'netflix' in domain_lower:
            return "Netflix"
        elif 'twitter' in domain_lower or 'x.com' in domain_lower:
            return "X Corp (Twitter)"
        elif 'linkedin' in domain_lower:
            return "Microsoft (LinkedIn)"
        elif 'vit.ac.in' in domain_lower:
            return "VIT (Vellore Institute of Technology)"
        elif '.edu' in domain_lower:
            return "Educational Institution"
        elif '.gov' in domain_lower:
            return "Government"
        elif '.ac.in' in domain_lower:
            return "Indian Academic Institution"
        else:
            # Try to extract ISP/Provider from domain name
            domain_parts = domain_lower.split('.')
            if len(domain_parts) > 1:
                # Return the main domain name as provider if it looks like a custom domain
                return domain_parts[-2].capitalize()
            return "Unknown Provider"
    except Exception as e:
        print(f"Error getting hosting provider: {e}")
        return "Unknown Provider"

def get_current_date():
    """Get current date and time in readable format"""
    try:
        now = datetime.now()
        # Format: "April 8th 2026 2:45:30 PM"
        day = now.day
        month = now.strftime("%B")
        year = now.year
        time_str = now.strftime("%I:%M:%S %p")  # 12-hour format with AM/PM
        
        # Add ordinal suffix to day
        if 10 <= day % 100 <= 20:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        
        return f"{month} {day}{suffix} {year} {time_str}"
    except Exception as e:
        print(f"Error getting current date: {e}")
        return datetime.now().strftime("%B %d, %Y %I:%M:%S %p")

def get_ssl_certificate_info(url_string):
    """Extract SSL certificate information from URL"""
    try:
        # Parse the URL to get domain
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Get SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate issuer and subject
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                
                issuer = issuer_dict.get('organizationName', 'Unknown Issuer')
                common_name = subject_dict.get('commonName', domain)
                
                return {
                    "issuer": issuer,
                    "domain": common_name,
                    "verified": True
                }
    except Exception as e:
        print(f"SSL Certificate error for {url_string}: {e}")
        return {
            "issuer": "Certificate Not Available",
            "domain": urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string).netloc,
            "verified": False
        }

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
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        user_url = data.get('url', '').strip()
        if not user_url:
            return jsonify({"error": "No URL provided"}), 400
        
        print(f"Scanning URL: {user_url}")
        result = check_url_safety(user_url)

        screenshot_path = take_screenshot(user_url)
        result["screenshot"] = screenshot_path
        print(f"Screenshot captured: {'Success' if screenshot_path else 'Failed'}")
        
        # Get SSL certificate information
        cert_info = get_ssl_certificate_info(user_url)
        result["certificate"] = cert_info
        print(f"Certificate info: {cert_info}")
        
        # Extract brand, TLD, and host information
        brand_info = extract_brand_and_tld(user_url)
        result["brand"] = brand_info["brand"]
        result["tld"] = brand_info["tld"]
        print(f"Brand: {brand_info['brand']}, TLD: {brand_info['tld']}")
        
        # Get host/IP information
        host_ip = get_host_from_url(user_url)
        result["host"] = host_ip
        print(f"Host: {host_ip}")
        
        # Get IP address
        ip_address = get_ip_address(user_url)
        result["ip_address"] = ip_address
        print(f"IP Address: {ip_address}")
        
        # Get hosting provider information
        hosting_provider = get_hosting_provider(user_url)
        result["hosting_provider"] = hosting_provider
        print(f"Hosting Provider: {hosting_provider}")
        
        # Get current date
        current_date = get_current_date()
        result["detection_date"] = current_date
        print(f"Detection Date: {current_date}")
        
        # Add additional info for phishing URLs
        if result["status"] == "Phishing":
            result["warning"] = "This URL has been flagged as potentially malicious. Screenshot capture may be limited for security reasons."
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in scan route: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)