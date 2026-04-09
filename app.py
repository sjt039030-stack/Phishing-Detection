from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import tensorflow as tf
from tensorflow.keras.models import load_model
import numpy as np
import joblib
import os
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import math
import re
import base64
import sys
import traceback
import requests
import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import threading
import logging
from playwright.async_api import async_playwright

# ========================================
# 🔧 CONFIGURATION
# ========================================

app = FastAPI()

# API Keys
MICROLINK_API_KEY = "a634cbd02d5c266b38cc"
SCREENSHOTONE_API_KEY = "c43769f7bf336949b205"

# Thread pool
executor = ThreadPoolExecutor(max_workers=3)

# Cache
screenshot_cache = {}
cache_lock = threading.Lock()

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("Loading Model, Scaler, and TLD Encoder...")
sys.stdout.flush()

try:
    model = load_model("tabular_cnn_lstm_model.h5")
    scaler = joblib.load("tabular_scaler.pkl")
    tld_encoder = joblib.load("tabular_tld_encoder.pkl")
    print("✅ Model loaded!")
    sys.stdout.flush()
except Exception as e:
    print(f"❌ Error loading assets: {e}")
    sys.stdout.flush()
    model = None
    scaler = None
    tld_encoder = None

# ========================================
# 💾 CACHE UTILITIES
# ========================================

def get_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()

def get_cached_screenshot(url):
    cache_key = get_cache_key(url)
    with cache_lock:
        if cache_key in screenshot_cache:
            return screenshot_cache[cache_key]
    return None

def cache_screenshot(url, screenshot_b64):
    cache_key = get_cache_key(url)
    with cache_lock:
        screenshot_cache[cache_key] = screenshot_b64

# ========================================
# 📸 PLAYWRIGHT SCREENSHOT (SERVERLESS-OPTIMIZED)
# ========================================

async def take_screenshot_playwright(url):
    """
    🚀 Playwright - Direct browser rendering
    Timeout: 10 seconds (Vercel limit)
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    try:
        print(f"    📸 Playwright (direct)...", flush=True)
        sys.stdout.flush()
        
        # Check cache
        cached = get_cached_screenshot(url)
        if cached:
            print(f"      💾 Using cached screenshot", flush=True)
            return cached
        
        # Launch Playwright
        async with async_playwright() as p:
            # Use chromium only - lighter for serverless
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            
            page = await browser.new_page(viewport={"width": 1280, "height": 720})
            
            # Navigate with timeout
            await page.goto(url, wait_until="networkidle", timeout=8000)
            
            # Take screenshot
            screenshot_bytes = await page.screenshot(type="png")
            
            # Cleanup
            await browser.close()
            
            # Convert to base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            cache_screenshot(url, f"data:image/png;base64,{screenshot_b64}")
            
            size_kb = len(screenshot_b64) // 1024
            print(f"      ✅ Playwright: {size_kb}KB", flush=True)
            sys.stdout.flush()
            return f"data:image/png;base64,{screenshot_b64}"
        
    except Exception as e:
        print(f"    ❌ Playwright error: {str(e)[:80]}", flush=True)
        sys.stdout.flush()
        return None

async def take_screenshot_microlink(url):
    """Fallback: Microlink API"""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    try:
        print(f"    📸 Microlink (fallback)...", flush=True)
        sys.stdout.flush()
        
        cached = get_cached_screenshot(url)
        if cached:
            return cached
        
        api_url = (
            f"https://api.microlink.io?"
            f"url={requests.utils.quote(url)}"
            f"&screenshot=true"
            f"&embed=screenshot"
            f"&apiToken={MICROLINK_API_KEY}"
        )
        
        response = requests.get(api_url, timeout=6)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'screenshot' in data['data']:
                screenshot_url = data['data']['screenshot']['url']
                img_response = requests.get(screenshot_url, timeout=4)
                if img_response.status_code == 200:
                    screenshot_b64 = base64.b64encode(img_response.content).decode('utf-8')
                    cache_screenshot(url, f"data:image/jpeg;base64,{screenshot_b64}")
                    size_kb = len(screenshot_b64) // 1024
                    print(f"      ✅ Microlink: {size_kb}KB", flush=True)
                    return f"data:image/jpeg;base64,{screenshot_b64}"
        
        return None
        
    except Exception as e:
        print(f"    ❌ Microlink error: {str(e)[:60]}", flush=True)
        sys.stdout.flush()
        return None

async def take_screenshot(url):
    """Primary: Playwright, Fallback: Microlink"""
    screenshot = await take_screenshot_playwright(url)
    if screenshot:
        return screenshot
    
    screenshot = await take_screenshot_microlink(url)
    if screenshot:
        return screenshot
    
    print(f"    ❌ All screenshot methods failed", flush=True)
    return None

# ========================================
# 🤖 ML PREDICTION
# ========================================

def calculate_entropy(text):
    if not text or not isinstance(text, str):
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += -p_x * math.log2(p_x)
    return entropy

def check_url_safety(url_string):
    if not scaler or not model or not tld_encoder:
        return {
            "status": "Unable to Process",
            "message": "Model not loaded",
            "color": "#ff9800",
            "probability": 0
        }
    
    try:
        u = str(url_string).lower()
        https_flag = 1 if u.startswith('https') else 0
        if not u.startswith('http'): 
            u = 'https://' + u
            
        parsed = urlparse(u)
        domain = parsed.netloc
        domain_parts = domain.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else ''
        
        try:
            encoded_tld = tld_encoder.transform([tld])[0]
        except ValueError:
            encoded_tld = 0
            
        features = [
            len(u), len(domain), encoded_tld, calculate_entropy(u),
            domain.count('.'), sum(c.isdigit() for c in u),
            len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]', u)),
            u.count('/'), https_flag, calculate_entropy(domain)
        ]
        
        features_array = np.array(features).reshape(1, -1)
        scaled_features = scaler.transform(features_array)
        cnn_ready_features = np.expand_dims(scaled_features, axis=2)
        
        prob = float(model.predict(cnn_ready_features, verbose=0)[0][0])
        
        if prob > 0.5:
            return {
                "status": "Phishing",
                "message": f"⚠️ {prob*100:.2f}% Phishing Detected",
                "color": "#dc3545",
                "probability": prob
            }
        else:
            return {
                "status": "Safe",
                "message": f"✅ {(1-prob)*100:.2f}% Safe",
                "color": "#28a745",
                "probability": prob
            }
            
    except Exception as e:
        print(f"❌ Prediction error: {str(e)}", flush=True)
        return {
            "status": "Error",
            "message": "Failed to analyze URL",
            "color": "#ff9800",
            "probability": 0
        }

# ========================================
# 🛠️ UTILITIES
# ========================================

def get_ip_address(url):
    try:
        print(f"    🔍 Resolving IP...", flush=True)
        socket.setdefaulttimeout(2)
        domain = get_host_from_url(url)
        ip = socket.gethostbyname(domain)
        print(f"      ✅ IP: {ip}", flush=True)
        return ip
    except:
        return "Unknown"

def extract_brand_and_tld(url_string):
    try:
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc
        domain_parts = domain.split('.')
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else 'unknown'
        brand = domain_parts[-2].lower() if len(domain_parts) >= 2 else domain.lower()
        return {"brand": brand.capitalize(), "tld": tld.upper(), "full_domain": domain}
    except:
        return {"brand": "unknown", "tld": "unknown", "full_domain": url_string}

def get_host_from_url(url_string):
    try:
        parsed_url = urlparse(url_string if url_string.startswith(('http://', 'https://')) else 'https://' + url_string)
        domain = parsed_url.netloc.split(':')[0] if ':' in parsed_url.netloc else parsed_url.netloc
        return domain
    except:
        return "Unknown"

def get_hosting_provider(url_string):
    try:
        domain = get_host_from_url(url_string).lower()
        if 'google' in domain:
            return "Google"
        elif 'microsoft' in domain or 'azure' in domain:
            return "Microsoft"
        elif 'amazon' in domain or 'aws' in domain:
            return "Amazon Web Services"
        elif 'cloudflare' in domain:
            return "Cloudflare"
        else:
            parts = domain.split('.')
            return parts[-2].capitalize() if len(parts) > 1 else "Unknown"
    except:
        return "Unknown"

def get_current_date():
    try:
        now = datetime.now()
        day, month, year = now.day, now.strftime("%B"), now.year
        time_str = now.strftime("%I:%M:%S %p")
        suffix = 'th' if 10 <= day % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        return f"{month} {day}{suffix}, {year} at {time_str}"
    except:
        return datetime.now().strftime("%B %d, %Y %I:%M:%S %p")

def get_ssl_certificate_info(url_string):
    try:
        domain = get_host_from_url(url_string)
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                return {
                    "issuer": issuer_dict.get('organizationName', 'Unknown'),
                    "domain": subject_dict.get('commonName', domain),
                    "verified": True
                }
    except:
        return {
            "issuer": "Not Available",
            "domain": get_host_from_url(url_string),
            "verified": False
        }

# ========================================
# 🌐 ROUTES
# ========================================

@app.get("/")
async def home():
    return {"message": "Phishing Detection API"}

@app.post("/scan")
async def scan(request_data: dict):
    """
    Main scan endpoint
    """
    try:
        print(f"\n{'='*70}\n🔍 SCAN REQUEST\n{'='*70}", flush=True)
        sys.stdout.flush()
        
        user_url = request_data.get('url', '').strip()
        if not user_url:
            raise HTTPException(status_code=400, detail="No URL provided")
        
        print(f"🔗 URL: {user_url}", flush=True)
        sys.stdout.flush()
        
        # ML Prediction (sync, instant)
        print(f"  ⚡ ML Prediction...", flush=True)
        result = check_url_safety(user_url)
        
        # Screenshot (async, with timeout)
        print(f"  ⚡ Screenshot (async)...", flush=True)
        try:
            screenshot = await asyncio.wait_for(
                take_screenshot(user_url),
                timeout=10.0
            )
            result["screenshot"] = screenshot
        except Exception as e:
            print(f"  ⚠️ Screenshot timeout/error", flush=True)
            result["screenshot"] = None
        
        # SSL Certificate (sync)
        print(f"  ⚡ SSL Certificate...", flush=True)
        result["certificate"] = get_ssl_certificate_info(user_url)
        
        # IP Address (sync)
        print(f"  ⚡ IP Address...", flush=True)
        result["ip_address"] = get_ip_address(user_url)
        
        # Metadata
        brand_info = extract_brand_and_tld(user_url)
        result["brand"] = brand_info["brand"]
        result["tld"] = brand_info["tld"]
        result["host"] = get_host_from_url(user_url)
        result["hosting_provider"] = get_hosting_provider(user_url)
        result["detection_date"] = get_current_date()
        
        if result["status"] == "Phishing":
            result["warning"] = "This URL has been flagged as malicious!"
        
        print(f"✅ SCAN COMPLETE: {result['status']}\n", flush=True)
        sys.stdout.flush()
        
        return JSONResponse(result, status_code=200)
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}", flush=True)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Server error")

# For Vercel
import asyncio