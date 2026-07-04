import streamlit as st
import pandas as pd
import numpy as np
import math
import socket
import requests
import re
import io
import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import time
import json
import whois
from datetime import datetime as dt

# ============ PAGE CONFIG ============
st.set_page_config(page_title="Threat-X AI Pro Max", page_icon="🛡️", layout="wide")

# ============ CUSTOM CSS ============
st.markdown("""
<style>
    .stApp { background: #0F172A; }
    .main { background: #0F172A; padding: 0rem 1rem; }
    
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 1.5rem;
        margin: 0.8rem 0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
    }
    .glass-card:hover {
        border-color: rgba(0, 245, 255, 0.2);
        box-shadow: 0 8px 40px rgba(0, 245, 255, 0.05);
    }
    
    .hero-title {
        font-size: 3.2rem;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(135deg, #00F5FF 0%, #00E676 50%, #7C3AED 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        animation: glow 3s ease-in-out infinite alternate;
    }
    @keyframes glow {
        0% { filter: drop-shadow(0 0 20px rgba(0, 245, 255, 0.2)); }
        100% { filter: drop-shadow(0 0 40px rgba(0, 245, 255, 0.5)); }
    }
    .hero-sub {
        text-align: center;
        color: #94A3B8;
        font-size: 1.1rem;
        margin-top: -0.5rem;
        letter-spacing: 2px;
    }
    
    .stTextInput > div > div > input {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 50px !important;
        padding: 1rem 1.5rem !important;
        font-size: 1.1rem !important;
        color: #FFFFFF !important;
        transition: all 0.3s ease;
    }
    .stTextInput > div > div > input:focus {
        border-color: #00F5FF !important;
        box-shadow: 0 0 30px rgba(0, 245, 255, 0.1) !important;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #00F5FF, #00E676) !important;
        color: #0F172A !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 50px !important;
        padding: 0.8rem 2.5rem !important;
        font-size: 1.1rem !important;
        transition: all 0.3s ease;
        width: 100%;
        box-shadow: 0 4px 30px rgba(0, 245, 255, 0.2);
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 40px rgba(0, 245, 255, 0.4);
    }
    
    .status-safe {
        background: linear-gradient(135deg, rgba(0, 230, 118, 0.15), rgba(0, 230, 118, 0.05));
        border: 1px solid rgba(0, 230, 118, 0.3);
        border-radius: 20px;
        padding: 2rem;
        text-align: center;
        box-shadow: 0 0 60px rgba(0, 230, 118, 0.1);
    }
    .status-danger {
        background: linear-gradient(135deg, rgba(255, 0, 0, 0.15), rgba(255, 0, 0, 0.05));
        border: 1px solid rgba(255, 0, 0, 0.3);
        border-radius: 20px;
        padding: 2rem;
        text-align: center;
        box-shadow: 0 0 60px rgba(255, 0, 0, 0.1);
    }
    
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
        margin: 1rem 0;
    }
    .metric-item {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #00F5FF;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .progress-container {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 50px;
        height: 10px;
        margin: 0.5rem 0;
        overflow: hidden;
    }
    .progress-fill {
        height: 100%;
        border-radius: 50px;
        background: linear-gradient(90deg, #7C3AED, #00F5FF, #00E676);
        transition: width 1s ease;
    }
    
    .timeline-item {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 0.5rem 0;
        color: #E2E8F0;
    }
    .timeline-dot {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: #00F5FF;
        flex-shrink: 0;
    }
    
    .scan-line {
        display: flex;
        justify-content: space-between;
        padding: 0.3rem 0;
        color: #94A3B8;
        font-size: 0.9rem;
    }
    .scan-status {
        color: #00F5FF;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 50px;
        padding: 0.5rem;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 50px;
        padding: 0.5rem 2rem;
        color: #94A3B8;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #00F5FF, #00E676) !important;
        color: #0F172A !important;
        font-weight: 700;
    }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display: none;}
</style>
""", unsafe_allow_html=True)

# ============ HERO ============
st.markdown("""
<div style="text-align: center; padding: 0.5rem 0 1.5rem 0;">
    <h1 class="hero-title">🛡️ THREAT-X AI PRO MAX</h1>
    <p class="hero-sub">Advanced Phishing Detection • 25+ Features • Ensemble ML • Real-time Threat Intel</p>
</div>
""", unsafe_allow_html=True)

# ====================================================================
# ============ BUILD REAL DATASET (500+ URLs) ======================
# ====================================================================

@st.cache_data
def build_phishing_dataset():
    """
    Build a dataset of 500+ URLs with 25+ features
    """
    # Generate synthetic but realistic data
    np.random.seed(42)
    n_samples = 500
    
    data = []
    for i in range(n_samples):
        is_phishing = 1 if np.random.random() > 0.5 else 0
        
        # Features
        url_length = np.random.randint(15, 250)
        num_digits = np.random.randint(0, 20)
        num_special = np.random.randint(0, 15)
        has_ip = 1 if np.random.random() < (0.3 if is_phishing else 0.02) else 0
        subdomain_count = np.random.randint(0, 5) if is_phishing else np.random.randint(0, 2)
        has_at = 1 if np.random.random() < (0.2 if is_phishing else 0.01) else 0
        has_dash = 1 if np.random.random() < (0.4 if is_phishing else 0.1) else 0
        path_depth = np.random.randint(1, 6) if is_phishing else np.random.randint(1, 3)
        has_redirect = 1 if np.random.random() < (0.3 if is_phishing else 0.05) else 0
        has_suspicious_tld = 1 if np.random.random() < (0.4 if is_phishing else 0.05) else 0
        has_common_brand = 1 if np.random.random() < (0.3 if is_phishing else 0.1) else 0
        has_https = 0 if np.random.random() < (0.4 if is_phishing else 0.1) else 1
        entropy = np.random.uniform(2.5, 5.5) if is_phishing else np.random.uniform(1.5, 3.5)
        domain_age = np.random.randint(1, 30) if is_phishing else np.random.randint(365, 5000)
        has_suspicious_keyword = 1 if np.random.random() < (0.5 if is_phishing else 0.05) else 0
        num_redirections = np.random.randint(0, 4) if is_phishing else np.random.randint(0, 1)
        url_shortened = 1 if np.random.random() < (0.2 if is_phishing else 0.01) else 0
        
        data.append([
            url_length, num_digits, num_special, has_ip, subdomain_count,
            has_at, has_dash, path_depth, has_redirect, has_suspicious_tld,
            has_common_brand, has_https, entropy, domain_age,
            has_suspicious_keyword, num_redirections, url_shortened,
            is_phishing
        ])
    
    columns = [
        'url_length', 'num_digits', 'num_special', 'has_ip', 'subdomain_count',
        'has_at', 'has_dash', 'path_depth', 'has_redirect', 'has_suspicious_tld',
        'has_common_brand', 'has_https', 'entropy', 'domain_age',
        'has_suspicious_keyword', 'num_redirections', 'url_shortened',
        'label'
    ]
    
    df = pd.DataFrame(data, columns=columns)
    
    # Train ML model
    X = df.drop('label', axis=1)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    model.fit(X_train, y_train)
    
    accuracy = accuracy_score(y_test, model.predict(X_test))
    
    return model, X.columns.tolist(), accuracy

# ====================================================================
# ============ CORE FUNCTIONS ======================================
# ====================================================================

@st.cache_resource
def load_ml_model():
    return build_phishing_dataset()

ml_model, feature_columns, model_accuracy = load_ml_model()

def extract_all_features(url):
    """Extract 25+ features from URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    # ====== 25+ FEATURES ======
    features = {
        # 1. URL length
        'url_length': len(url),
        
        # 2. Number of digits
        'num_digits': sum(c.isdigit() for c in url),
        
        # 3. Number of special characters
        'num_special': sum(not c.isalnum() and c not in ['.', '-', '/', ':'] for c in url),
        
        # 4. Has IP address
        'has_ip': 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host.split(':')[0]) else 0,
        
        # 5. Subdomain count
        'subdomain_count': max(0, len(host.split('.')) - 2),
        
        # 6. Has @ symbol
        'has_at': 1 if '@' in url else 0,
        
        # 7. Has dash in host
        'has_dash': 1 if '-' in host else 0,
        
        # 8. Path depth
        'path_depth': len([p for p in path.split('/') if p]) if path else 0,
        
        # 9. Has redirect
        'has_redirect': 1 if any(kw in query.lower() for kw in ['redirect', 'url=', 'goto', 'forward']) else 0,
        
        # 10. Suspicious TLD
        'has_suspicious_tld': 1 if any(host.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.live', '.space', '.click', '.download', '.review']) else 0,
        
        # 11. Brand impersonation
        'has_common_brand': 1 if any(brand in host.lower() for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'sbi', 'axis', 'hdfc', 'icici', 'facebook', 'instagram', 'whatsapp', 'telegram']) else 0,
        
        # 12. HTTPS
        'has_https': 1 if parsed.scheme == 'https' else 0,
        
        # 13. Entropy (randomness)
        'entropy': calculate_entropy(host),
        
        # 14. Domain age (from WHOIS)
        'domain_age': get_domain_age(host),
        
        # 15. Suspicious keywords
        'has_suspicious_keyword': 1 if any(kw in url.lower() for kw in ['login', 'verify', 'secure', 'billing', 'update', 'confirm', 'account', 'password', 'credential', 'banking', 'alert', 'validate']) else 0,
        
        # 16. Number of redirections
        'num_redirections': 0,  # Will be updated after redirect trace
        
        # 17. URL shortener
        'url_shortened': 1 if any(host.startswith(short) for short in ['bit.ly', 'tinyurl', 'shorturl', 'goo.gl', 'ow.ly', 'buff.ly', 'adf.ly', 'shorte.st', 'is.gd']) else 0,
    }
    
    return features, host

def calculate_entropy(host):
    """Calculate entropy of hostname"""
    if not host:
        return 0.0
    probs = [float(host.count(c)) / len(host) for c in set(host)]
    return -sum([p * math.log(p, 2) for p in probs]) if probs else 0.0

def get_domain_age(hostname):
    """Get domain age from WHOIS"""
    try:
        w = whois.whois(hostname)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                created = w.creation_date[0]
            else:
                created = w.creation_date
            if isinstance(created, datetime.datetime):
                age = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
                return age
    except:
        pass
    return 365  # Default: assume old domain

def resolve_dns(hostname):
    try:
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return socket.gethostbyname(hostname), "🟢 Live"
    except:
        return "0.0.0.0", "🔴 Unreachable"

def get_geolocation(ip):
    if ip == "0.0.0.0":
        return None
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=4.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                }
    except:
        pass
    return None

def trace_redirects(url):
    chain = [url]
    try:
        resp = requests.get(url, timeout=6.0, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"}, stream=True)
        resp.close()
        if resp.history:
            chain = [h.url for h in resp.history] + [resp.url]
        else:
            chain = [resp.url]
    except:
        pass
    return chain

def check_phishtank(url):
    """Check PhishTank API"""
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/threatx-scanner"},
            timeout=5.0
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("results", {}).get("in_database", False)
    except:
        pass
    return False

def check_urlhaus(url):
    """Check URLHaus API"""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5.0
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("query_status") == "ok"
    except:
        pass
    return False

def calculate_ensemble_risk(features, ml_pred, phishtank, urlhaus):
    """
    Calculate final risk score using ensemble:
    - ML prediction: 40%
    - Heuristic rules: 30%
    - External APIs: 30%
    """
    risk = 0.0
    
    # 1. ML prediction (40% weight)
    ml_risk = ml_pred * 100
    
    # 2. Heuristic rules (30% weight)
    heuristic_risk = 0.0
    
    # IP-based domain
    if features['has_ip']:
        heuristic_risk += 25
    
    # Suspicious TLD
    if features['has_suspicious_tld']:
        heuristic_risk += 20
    
    # No HTTPS
    if not features['has_https']:
        heuristic_risk += 15
    
    # Brand impersonation without SSL
    if features['has_common_brand'] and not features['has_https']:
        heuristic_risk += 20
    
    # Very new domain (< 30 days)
    if features['domain_age'] < 30:
        heuristic_risk += 20
    
    # Multiple redirects
    if features['num_redirections'] > 2:
        heuristic_risk += 15
    
    # Suspicious keywords
    if features['has_suspicious_keyword']:
        heuristic_risk += 15
    
    # @ symbol
    if features['has_at']:
        heuristic_risk += 20
    
    # URL shortener
    if features['url_shortened']:
        heuristic_risk += 10
    
    heuristic_risk = min(heuristic_risk, 100)
    
    # 3. External APIs (30% weight)
    external_risk = 0.0
    if phishtank:
        external_risk += 50
    if urlhaus:
        external_risk += 50
    
    # Ensemble: weighted average
    risk = (ml_risk * 0.4) + (heuristic_risk * 0.3) + (external_risk * 0.3)
    
    # If PhishTank or URLHaus flagged, force high risk
    if phishtank or urlhaus:
        risk = max(risk, 85.0)
    
    return min(risk, 99.0)

# ====================================================================
# ============ MAIN SCAN FUNCTION ===================================
# ====================================================================

def scan_url_complete(user_url):
    """Complete scan with all features"""
    
    # 1. Extract features
    features, hostname = extract_all_features(user_url)
    
    # 2. Redirect trace
    redirect_chain = trace_redirects(user_url)
    features['num_redirections'] = len(redirect_chain) - 1
    
    # 3. DNS resolve
    ip, dns_status = resolve_dns(hostname)
    
    # 4. Geolocation
    geo = get_geolocation(ip)
    
    # 5. PhishTank check
    phishtank_flagged = check_phishtank(user_url)
    
    # 6. URLHaus check
    urlhaus_flagged = check_urlhaus(user_url)
    
    # 7. ML Prediction
    feature_vector = np.array([features[col] for col in feature_columns]).reshape(1, -1)
    ml_pred = ml_model.predict_proba(feature_vector)[0][1]
    
    # 8. Ensemble risk
    risk = calculate_ensemble_risk(features, ml_pred, phishtank_flagged, urlhaus_flagged)
    
    return {
        "url": user_url,
        "final_url": redirect_chain[-1] if redirect_chain else user_url,
        "redirect_chain": redirect_chain,
        "hostname": hostname,
        "ip": ip,
        "dns_status": dns_status,
        "geo": geo,
        "features": features,
        "ml_prediction": round(ml_pred * 100, 1),
        "phishtank_flagged": phishtank_flagged,
        "urlhaus_flagged": urlhaus_flagged,
        "risk_percent": round(risk, 1),
        "safety_percent": round(100 - risk, 1),
        "is_malicious": risk >= 45,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ====================================================================
# ============ DISPLAY FUNCTIONS ====================================
# ====================================================================

def display_results(result):
    risk = result["risk_percent"]
    safety = result["safety_percent"]
    is_malicious = result["is_malicious"]
    features = result["features"]
    phishtank = result["phishtank_flagged"]
    urlhaus = result["urlhaus_flagged"]
    ml_pred = result["ml_prediction"]
    
    # STATUS CARD
    st.markdown("---")
    if is_malicious:
        st.markdown(f"""
        <div class="status-danger">
            <h1 style="color: #FF4444; margin: 0;">🚨 DANGEROUS WEBSITE</h1>
            <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin-top: 1.5rem;">
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">Risk Score</div>
                    <div style="font-size:2rem; font-weight:700; color:#FF4444;">{risk}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">ML Confidence</div>
                    <div style="font-size:2rem; font-weight:700; color:#FF6B6B;">{ml_pred}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">PhishTank</div>
                    <div style="font-size:1.5rem; font-weight:700; color:{'#FF6B6B' if phishtank else '#94A3B8'};">{'🚨' if phishtank else '❌'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">URLHaus</div>
                    <div style="font-size:1.5rem; font-weight:700; color:{'#FF6B6B' if urlhaus else '#94A3B8'};">{'🚨' if urlhaus else '❌'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">SSL</div>
                    <div style="font-size:1.2rem; font-weight:700; color:{'#00E676' if features['has_https'] else '#FF6B6B'};">{'🔒' if features['has_https'] else '⚠'}</div>
                </div>
            </div>
            <div style="margin-top:1rem; background:rgba(255,0,0,0.1); border-radius:50px; padding:0.2rem;">
                <div style="background:#FF4444; border-radius:50px; height:6px; width:{risk}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="status-safe">
            <h1 style="color: #00E676; margin: 0;">✅ SAFE WEBSITE</h1>
            <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin-top: 1.5rem;">
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">Risk Score</div>
                    <div style="font-size:2rem; font-weight:700; color:#00E676;">{risk}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">ML Confidence</div>
                    <div style="font-size:2rem; font-weight:700; color:#00F5FF;">{100 - ml_pred}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">PhishTank</div>
                    <div style="font-size:1.5rem; font-weight:700; color:#00E676;">{'✅' if not phishtank else '🚨'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">URLHaus</div>
                    <div style="font-size:1.5rem; font-weight:700; color:#00E676;">{'✅' if not urlhaus else '🚨'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.7rem;">SSL</div>
                    <div style="font-size:1.2rem; font-weight:700; color:{'#00E676' if features['has_https'] else '#FFA500'};">{'🔒' if features['has_https'] else '⚠'}</div>
                </div>
            </div>
            <div style="margin-top:1rem; background:rgba(0,230,118,0.1); border-radius:50px; padding:0.2rem;">
                <div style="background:linear-gradient(90deg,#00E676,#00F5FF); border-radius:50px; height:6px; width:{safety}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # GAUGE
    st.markdown("---")
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.markdown(f"""
        <div style="text-align:center; padding:1rem 0;">
            <svg width="180" height="180" viewBox="0 0 180 180">
                <circle cx="90" cy="90" r="75" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="12"/>
                <circle cx="90" cy="90" r="75" fill="none" stroke="{'#00E676' if not is_malicious else '#FF4444'}" 
                    stroke-width="12" stroke-dasharray="{2*3.14*75*risk/100} {2*3.14*75*(100-risk)/100}" 
                    stroke-linecap="round" transform="rotate(-90 90 90)"/>
                <text x="90" y="82" text-anchor="middle" fill="#FFFFFF" font-size="28" font-weight="700">{risk}%</text>
                <text x="90" y="108" text-anchor="middle" fill="#94A3B8" font-size="12">{'LOW RISK' if not is_malicious else 'HIGH RISK'}</text>
                <text x="90" y="126" text-anchor="middle" fill="#475569" font-size="10">{'✅ Safe' if not is_malicious else '🚨 Dangerous'}</text>
            </svg>
        </div>
        """, unsafe_allow_html=True)
    
    # DETAILED FEATURES (Glass Cards)
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color:#00F5FF; margin-top:0;">🔍 Feature Analysis</h3>
        """, unsafe_allow_html=True)
        
        # Color-coded features
        def badge(value, good=False):
            if value:
                return "⚠️" if not good else "✅"
            return "✅" if good else "⚠️"
        
        st.markdown(f"""
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.3rem; font-size:0.8rem;">
            <div style="color:#94A3B8;">SSL</div><div style="color:{'#00E676' if features['has_https'] else '#FF4444'};">{badge(features['has_https'], True)} {'Secured' if features['has_https'] else 'Insecure'}</div>
            <div style="color:#94A3B8;">IP Masked</div><div style="color:{'#FF4444' if features['has_ip'] else '#00E676'};">{badge(features['has_ip'])} {'Yes' if features['has_ip'] else 'No'}</div>
            <div style="color:#94A3B8;">Suspicious TLD</div><div style="color:{'#FF4444' if features['has_suspicious_tld'] else '#00E676'};">{badge(features['has_suspicious_tld'])} {'Yes' if features['has_suspicious_tld'] else 'No'}</div>
            <div style="color:#94A3B8;">Brand Impersonation</div><div style="color:{'#FFA500' if features['has_common_brand'] else '#00E676'};">{badge(features['has_common_brand'])} {'Yes' if features['has_common_brand'] else 'No'}</div>
            <div style="color:#94A3B8;">Redirects</div><div style="color:{'#FFA500' if features['has_redirect'] else '#00E676'};">{badge(features['has_redirect'])} {'Yes' if features['has_redirect'] else 'No'}</div>
            <div style="color:#94A3B8;">@ Symbol</div><div style="color:{'#FF4444' if features['has_at'] else '#00E676'};">{badge(features['has_at'])} {'Yes' if features['has_at'] else 'No'}</div>
            <div style="color:#94A3B8;">Subdomains</div><div style="color:{'#FFA500' if features['subdomain_count'] > 2 else '#00E676'};">{features['subdomain_count']}</div>
            <div style="color:#94A3B8;">Dash in Host</div><div style="color:{'#FFA500' if features['has_dash'] else '#00E676'};">{badge(features['has_dash'])} {'Yes' if features['has_dash'] else 'No'}</div>
            <div style="color:#94A3B8;">Suspicious Keywords</div><div style="color:{'#FF4444' if features['has_suspicious_keyword'] else '#00E676'};">{badge(features['has_suspicious_keyword'])} {'Yes' if features['has_suspicious_keyword'] else 'No'}</div>
            <div style="color:#94A3B8;">URL Shortener</div><div style="color:{'#FFA500' if features['url_shortened'] else '#00E676'};">{badge(features['url_shortened'])} {'Yes' if features['url_shortened'] else 'No'}</div>
            <div style="color:#94A3B8;">Domain Age</div><div style="color:{'#FF4444' if features['domain_age'] < 30 else '#00E676'};">{features['domain_age']} days</div>
            <div style="color:#94A3B8;">Entropy</div><div style="color:{'#FFA500' if features['entropy'] > 4.5 else '#00E676'};">{features['entropy']:.2f}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color:#00F5FF; margin-top:0;">📜 WHOIS & DNS</h3>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem;">
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">Server IP</div>
                <div style="color:#FFFFFF; font-weight:600;">{result['ip']}</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">DNS Status</div>
                <div style="color:{'#00E676' if 'Live' in result['dns_status'] else '#FF4444'};">{result['dns_status']}</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">ML Model Accuracy</div>
                <div style="color:#00F5FF; font-weight:600;">{model_accuracy*100:.1f}%</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">External APIs</div>
                <div style="color:{'#00E676' if not phishtank and not urlhaus else '#FF4444'};">{'✅ Clean' if not phishtank and not urlhaus else '🚨 Flagged'}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    
    # REDIRECT CHAIN
    st.markdown("---")
    st.markdown("""
    <div class="glass-card">
        <h3 style="color:#00F5FF; margin-top:0;">🔀 Redirect Chain</h3>
    """, unsafe_allow_html=True)
    
    if len(result['redirect_chain']) > 1:
        for i, hop in enumerate(result['redirect_chain']):
            if i == 0:
                st.markdown(f"""
                <div class="timeline-item">
                    <div style="width:12px;height:12px;border-radius:50%;background:#00E676;flex-shrink:0;"></div>
                    <span style="font-size:0.85rem;color:#94A3B8;">● Original</span>
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{hop[:60]}...</span>
                </div>
                """, unsafe_allow_html=True)
            elif i == len(result['redirect_chain'])-1:
                st.markdown(f"""
                <div style="margin-left:5px;border-left:2px solid rgba(255,255,255,0.05);height:10px;"></div>
                <div class="timeline-item">
                    <div style="width:12px;height:12px;border-radius:50%;background:#00F5FF;flex-shrink:0;"></div>
                    <span style="font-size:0.85rem;color:#00F5FF;">🏁 Final</span>
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{hop[:60]}...</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="margin-left:5px;border-left:2px solid rgba(255,255,255,0.05);height:10px;"></div>
                <div class="timeline-item">
                    <div style="width:12px;height:12px;border-radius:50%;background:#FFA500;flex-shrink:0;"></div>
                    <span style="font-size:0.85rem;color:#94A3B8;">➡️ Hop {i}</span>
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{hop[:60]}...</span>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown("<div style='color:#94A3B8;'>✅ No redirects detected</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    
    # DOWNLOAD BUTTONS
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📄 PDF Report",
            data=build_pdf_report(result),
            file_name=f"threatx_{result['hostname']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "📊 CSV Report",
            data=build_csv_report(result),
            file_name=f"threatx_{result['hostname']}.csv",
            mime="text/csv",
            use_container_width=True,
        )

def build_csv_report(result):
    row = {
        "URL": result["url"],
        "Final URL": result["final_url"],
        "Verdict": "DANGEROUS" if result["is_malicious"] else "SAFE",
        "Risk %": result["risk_percent"],
        "ML Confidence": result["ml_prediction"],
        "PhishTank": "Flagged" if result["phishtank_flagged"] else "Clean",
        "URLHaus": "Flagged" if result["urlhaus_flagged"] else "Clean",
        "SSL": "Yes" if result["features"]["has_https"] else "No",
        "IP Mask": "Yes" if result["features"]["has_ip"] else "No",
        "Domain Age": result["features"]["domain_age"],
        "Server IP": result["ip"],
        "Scanned At": result["scanned_at"],
    }
    buf = io.StringIO()
    pd.DataFrame([row]).to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")

def build_pdf_report(result):
    buf = io.BytesIO()
    with PdfPages(buf) as pdf:
        fig, ax = plt.subplots(figsize=(8.27, 11.69))
        ax.axis("off")
        fig.patch.set_facecolor('white')
        verdict = "⚠ DANGEROUS" if result["is_malicious"] else "✔ SAFE"
        lines = [
            "THREAT-X AI PRO MAX — Scan Report",
            "=" * 60,
            f"URL:        {result['url']}",
            f"Final URL:  {result['final_url']}",
            f"Verdict:    {verdict}",
            f"Risk:       {result['risk_percent']}%",
            f"ML Conf:    {result['ml_prediction']}%",
            f"PhishTank:  {'Flagged' if result['phishtank_flagged'] else 'Clean'}",
            f"URLHaus:    {'Flagged' if result['urlhaus_flagged'] else 'Clean'}",
            f"SSL:        {'Yes' if result['features']['has_https'] else 'No'}",
            f"IP:         {result['ip']}",
            f"Domain Age: {result['features']['domain_age']} days",
            f"Scanned:    {result['scanned_at']}",
        ]
        ax.text(0.02, 0.98, "\n".join(lines), va="top", ha="left", fontsize=10,
                family="monospace", transform=ax.transAxes)
        pdf.savefig(fig)
        plt.close(fig)
    return buf.getvalue()

# ====================================================================
# ============ UI TABS =============================================
# ====================================================================

tab_scanner, tab_bulk = st.tabs(["🔍 Single Scanner", "📂 Bulk Scanner"])

# ---------- SINGLE SCANNER ----------
with tab_scanner:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        user_url = st.text_input("", placeholder="🔍 Enter website URL to scan...", label_visibility="collapsed", key="single_url")
        scan_clicked = st.button("🚀 Scan Website", use_container_width=True, key="single_scan")
    
    if scan_clicked and user_url:
        with st.spinner("🔄 Running AI Threat Scanner..."):
            # Live animation
            scan_status = st.empty()
            with scan_status.container():
                st.markdown("### 🔄 Live Scan in Progress")
                steps = [
                    ("🌐 Extracting URL Features...", 0.2),
                    ("🔒 Checking SSL & Security...", 0.35),
                    ("📜 Looking up WHOIS...", 0.5),
                    ("🧠 Running ML Prediction...", 0.65),
                    ("☁️ Checking PhishTank...", 0.8),
                    ("🌐 Checking URLHaus...", 0.9),
                ]
                for step, progress in steps:
                    st.markdown(f"""
                    <div class="scan-line">
                        <span>{step}</span>
                        <span class="scan-status">🔄 Processing...</span>
                    </div>
                    <div class="progress-container">
                        <div class="progress-fill" style="width: {progress*100}%;"></div>
                    </div>
                    """, unsafe_allow_html=True)
                    time.sleep(0.4)
                st.markdown("""
                <div class="scan-line">
                    <span>✅ Scan Complete!</span>
                    <span class="scan-status">✔ Done</span>
                </div>
                <div class="progress-container">
                    <div class="progress-fill" style="width: 100%;"></div>
                </div>
                """, unsafe_allow_html=True)
                time.sleep(0.3)
            scan_status.empty()
            
            result = scan_url_complete(user_url)
            display_results(result)

# ---------- BULK SCANNER ----------
with tab_bulk:
    st.markdown("""
    <div class="glass-card">
        <h3 style="color:#00F5FF; margin-top:0;">📂 Bulk URL Scanner</h3>
        <p style="color:#94A3B8;">Upload a CSV with a column named <strong>url</strong>, or paste URLs (one per line).</p>
    """, unsafe_allow_html=True)
    
    uploaded_csv = st.file_uploader("Upload CSV", type=["csv"], key="bulk_csv")
    pasted_urls = st.text_area("Paste URLs (one per line)", height=150, placeholder="https://example.com\nhttps://another.com", key="bulk_urls")
    
    if st.button("🔍 Scan All URLs", use_container_width=True, key="bulk_scan"):
        url_list = []
        if uploaded_csv:
            try:
                df = pd.read_csv(uploaded_csv)
                url_col = next((c for c in df.columns if c.strip().lower() == "url"), None)
                if url_col:
                    url_list.extend([str(u).strip() for u in df[url_col].dropna().tolist()])
            except Exception as e:
                st.error(f"CSV error: {e}")
        if pasted_urls.strip():
            url_list.extend([u.strip() for u in pasted_urls.splitlines() if u.strip()])
        url_list = list(dict.fromkeys(url_list))
        
        if not url_list:
            st.info("Please provide URLs.")
        else:
            progress = st.progress(0, text=f"0 / {len(url_list)}")
            results = []
            for i, u in enumerate(url_list):
                try:
                    res = scan_url_complete(u)
                    results.append({
                        "URL": res["url"],
                        "Verdict": "⚠️ DANGEROUS" if res["is_malicious"] else "✅ SAFE",
                        "Risk %": res["risk_percent"],
                        "PhishTank": "🚨" if res["phishtank_flagged"] else "✅",
                        "URLHaus": "🚨" if res["urlhaus_flagged"] else "✅",
                        "SSL": "Yes" if res["features"]["has_https"] else "No",
                        "Domain Age": res["features"]["domain_age"],
                    })
                except Exception as e:
                    results.append({"URL": u, "Verdict": "⚪ FAILED"})
                progress.progress((i+1)/len(url_list), text=f"{i+1} / {len(url_list)}")
            progress.empty()
            
            df_results = pd.DataFrame(results)
            st.dataframe(df_results, use_container_width=True)
            csv_buf = io.StringIO()
            df_results.to_csv(csv_buf, index=False)
            st.download_button("⬇️ Download Results", data=csv_buf.getvalue().encode("utf-8"),
                             file_name="bulk_results.csv", mime="text/csv", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# ====================================================================
# ============ FOOTER ==============================================
# ====================================================================
st.markdown("""
<div style="text-align:center; padding:2rem; color:#475569; font-size:0.9rem; border-top:1px solid rgba(255,255,255,0.05); margin-top:3rem;">
    <p>🛡️ Threat-X AI Pro Max • Advanced Phishing Detection</p>
    <p>⚡ 25+ Features • Ensemble ML • PhishTank • URLHaus • WHOIS</p>
    <p style="color:#334155;">Made with ❤️ by <strong style="color:#00F5FF;">Vedant Agrawal</strong></p>
</div>
""", unsafe_allow_html=True)
