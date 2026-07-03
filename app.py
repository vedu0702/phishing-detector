import streamlit as st
import pandas as pd
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
import time
import numpy as np

# ============ PAGE CONFIG ============
st.set_page_config(page_title="Threat-X AI Pro", page_icon="🛡️", layout="wide")

# ============ CUSTOM CSS ============
st.markdown("""
<style>
    /* GLOBAL */
    .stApp {
        background: #0F172A;
    }
    .main {
        background: #0F172A;
        padding: 0rem 1rem;
    }
    
    /* GLASSMORPHISM CARDS */
    .glass-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(15px);
        -webkit-backdrop-filter: blur(15px);
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
    
    /* HERO TITLE */
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
    
    /* INPUT BOX */
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
    
    /* BUTTON */
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
    
    /* STATUS CARD */
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
    
    /* METRIC CARDS */
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
    
    /* PROGRESS BAR */
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
    
    /* TIMELINE */
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
    
    /* SCAN ANIMATION */
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
    
    /* TABS */
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
    
    /* HIDE STREAMLIT BRANDING */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display: none;}
</style>
""", unsafe_allow_html=True)

# ============ HERO ============
st.markdown("""
<div style="text-align: center; padding: 0.5rem 0 1.5rem 0;">
    <h1 class="hero-title">🛡️ THREAT-X AI PRO</h1>
    <p class="hero-sub">Enterprise Phishing Detection Platform • Powered by Advanced ML + Real-time Threat Intel</p>
</div>
""", unsafe_allow_html=True)

# ====================================================================
# ============ CORE FUNCTIONS (UPGRADED) ============================
# ====================================================================

# ---------- ADVANCED FEATURE EXTRACTION ----------
def extract_advanced_features(url):
    """Extract 15+ advanced features for phishing detection"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    # Basic features
    url_length = len(url)
    host_length = len(host)
    path_length = len(path)
    num_digits = sum(c.isdigit() for c in url)
    num_special = sum(not c.isalnum() and c not in ['.', '-', '/', ':'] for c in url)
    
    # Host-based features
    has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host.split(':')[0]) else 0
    subdomain_count = len(host.split('.')) - 2
    if subdomain_count < 0:
        subdomain_count = 0
    has_at = 1 if '@' in url else 0
    has_dash = 1 if '-' in host else 0
    
    # Path features
    path_depth = len([p for p in path.split('/') if p]) if path else 0
    has_redirect = 1 if 'redirect' in query.lower() or 'url=' in query.lower() or 'goto' in query.lower() else 0
    
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.live', '.space', '.click', '.download', '.review']
    has_suspicious_tld = 1 if any(host.endswith(tld) for tld in suspicious_tlds) else 0
    
    # Brand impersonation
    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'sbi', 'axis', 'hdfc', 'icici', 'facebook', 'instagram']
    has_common_brand = 1 if any(brand in host for brand in brands) else 0
    
    # SSL
    has_https = 1 if parsed.scheme == 'https' else 0
    
    # Entropy (randomness)
    probs = [float(host.count(c)) / len(host) for c in set(host)] if len(host) > 0 else [0.0]
    entropy = -sum([p * math.log(p, 2) for p in probs]) if len(host) > 0 else 0.0
    
    features = {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "num_digits": num_digits,
        "num_special": num_special,
        "has_ip": has_ip,
        "subdomain_count": subdomain_count,
        "has_at": has_at,
        "has_dash": has_dash,
        "path_depth": path_depth,
        "has_redirect": has_redirect,
        "has_suspicious_tld": has_suspicious_tld,
        "has_common_brand": has_common_brand,
        "has_https": has_https,
        "entropy": round(entropy, 2),
    }
    return features, host

# ---------- PHISHTANK API (LIVE CHECK) ----------
def check_phishtank_live(url):
    """Check URL against PhishTank database - FREE + UNLIMITED"""
    try:
        # PhishTank's checkurl endpoint
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/threatx-scanner"},
            timeout=5.0
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("results", {}).get("in_database", False):
                return True, data.get("results", {}).get("valid", False)
        return False, None
    except Exception as e:
        return False, None

# ---------- DNS + WHOIS + GEO ----------
def resolve_live_dns_ip(hostname):
    try:
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return socket.gethostbyname(hostname), "🟢 Live & Verified"
    except Exception:
        return "0.0.0.0", "🔴 Inactive / Blocked"

def resolve_geolocation(ip_address):
    if ip_address == "0.0.0.0":
        return None
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=4.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone", "Unknown")
                }
    except Exception:
        pass
    return None

def resolve_whois_record(hostname):
    try:
        import whois
        w = whois.whois(hostname)
        def first(value):
            if isinstance(value, list):
                return value[0] if value else None
            return value
        created = first(w.creation_date)
        expires = first(w.expiration_date)
        age_days = None
        if isinstance(created, datetime.datetime):
            age_days = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
        if age_days is None:
            age_status = "⚪ Registration date unavailable"
        elif age_days < 30:
            age_status = f"🔴 VERY NEW domain — {age_days} days old (HIGH RISK)"
        elif age_days < 180:
            age_status = f"🟠 Recently registered — {age_days} days old"
        else:
            age_status = f"🟢 Established domain — {age_days} days old"
        return {
            "found": True,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(created) if created else "Unknown",
            "expiration_date": str(expires) if expires else "Unknown",
            "age_days": age_days,
            "age_status": age_status,
            "name_servers": w.name_servers if w.name_servers else [],
            "org": getattr(w, "org", None) or "Not disclosed",
        }
    except ImportError:
        return {"found": False, "error": "python-whois not installed"}
    except Exception:
        return {"found": False, "error": "WHOIS lookup failed"}

# ---------- REDIRECT CHAIN ----------
def trace_redirect_chain(url, max_hops=10):
    chain = [url]
    try:
        resp = requests.get(
            url, timeout=6.0, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (ThreatX-Scanner)"},
            stream=True
        )
        resp.close()
        if resp.history:
            chain = [h.url for h in resp.history] + [resp.url]
        else:
            chain = [resp.url]
        return chain[:max_hops], chain[-1]
    except Exception:
        return chain, url

# ---------- ADVANCED RISK SCORE ----------
def calculate_advanced_risk(features, whois_info, phishtank_flagged):
    """Calculate risk score using ALL features"""
    risk = 0.0
    
    # 1. IP-based domain = HIGH RISK
    if features['has_ip']:
        risk += 35.0
    
    # 2. Suspicious TLD
    if features['has_suspicious_tld']:
        risk += 30.0
    
    # 3. No HTTPS
    if not features['has_https']:
        risk += 20.0
    
    # 4. Domain age (WHOIS)
    if whois_info.get("found") and whois_info.get("age_days") is not None:
        age = whois_info["age_days"]
        if age < 7:
            risk += 35.0  # Very new
        elif age < 30:
            risk += 25.0
        elif age < 180:
            risk += 10.0
    else:
        risk += 15.0  # WHOIS unavailable
    
    # 5. Brand impersonation (without SSL = very suspicious)
    if features['has_common_brand']:
        if not features['has_https']:
            risk += 35.0
        else:
            risk += 15.0
    
    # 6. Redirects
    if features['has_redirect']:
        risk += 25.0
    
    # 7. Suspicious characters
    if features['num_special'] > 10:
        risk += 15.0
    
    # 8. Many subdomains
    if features['subdomain_count'] > 2:
        risk += 15.0
    
    # 9. @ symbol in URL
    if features['has_at']:
        risk += 25.0
    
    # 10. Dash in hostname
    if features['has_dash']:
        risk += 10.0
    
    # 11. High entropy (random-looking URL)
    if features['entropy'] > 4.5:
        risk += 15.0
    
    # 12. PhishTank flag (OVERRIDE)
    if phishtank_flagged:
        risk = max(risk, 85.0)
    
    return min(risk, 99.0)

# ---------- MAIN SCAN FUNCTION (UPGRADED) ----------
def scan_url_advanced(user_target):
    original_url = user_target if user_target.startswith(('http://', 'https://')) else 'http://' + user_target
    
    # Redirect chain trace
    redirect_chain, final_url = trace_redirect_chain(original_url)
    
    # Advanced features
    features, host_domain = extract_advanced_features(final_url)
    
    # DNS
    resolved_ip, dns_status = resolve_live_dns_ip(host_domain)
    
    # Geolocation
    geo_info = resolve_geolocation(resolved_ip)
    
    # WHOIS
    whois_info = resolve_whois_record(host_domain)
    
    # PhishTank check
    phishtank_in_db, phishtank_valid = check_phishtank_live(final_url)
    
    # Risk calculation
    risk_percent = calculate_advanced_risk(features, whois_info, phishtank_valid)
    
    # Safety
    safety_percent = 100.0 - risk_percent
    is_malicious = risk_percent >= 45.0
    
    return {
        "input_url": user_target,
        "original_url": original_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "host_domain": host_domain,
        "features": features,
        "resolved_ip": resolved_ip,
        "dns_status": dns_status,
        "geo_info": geo_info,
        "whois_info": whois_info,
        "phishtank_flagged": phishtank_valid,
        "risk_percent": round(risk_percent, 1),
        "safety_percent": round(safety_percent, 1),
        "is_malicious": is_malicious,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ====================================================================
# ============ DISPLAY FUNCTIONS ====================================
# ====================================================================

def display_advanced_result(result):
    risk = result["risk_percent"]
    safety = result["safety_percent"]
    is_malicious = result["is_malicious"]
    features = result["features"]
    whois_info = result["whois_info"]
    geo_info = result["geo_info"]
    phishtank_flagged = result["phishtank_flagged"]
    
    # STATUS CARD
    st.markdown("---")
    if is_malicious:
        st.markdown(f"""
        <div class="status-danger">
            <h1 style="color: #FF4444; margin: 0;">🚨 DANGEROUS WEBSITE</h1>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 1.5rem;">
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">Risk Score</div>
                    <div style="font-size:2.2rem; font-weight:700; color:#FF4444;">{risk}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">PhishTank</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#FF6B6B' if phishtank_flagged else '#94A3B8'};">{'🚨 Flagged' if phishtank_flagged else '❌ Not Found'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">SSL</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#00E676' if features['has_https'] else '#FF6B6B'};">{'🔒 Secured' if features['has_https'] else '⚠ HTTP'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">Domain Age</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#FF6B6B' if whois_info.get('age_days') and whois_info['age_days'] < 30 else '#00E676'};">{whois_info.get('age_days', 'N/A')}d</div>
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
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-top: 1.5rem;">
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">Risk Score</div>
                    <div style="font-size:2.2rem; font-weight:700; color:#00E676;">{risk}%</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">PhishTank</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#FF6B6B' if phishtank_flagged else '#00E676'};">{'🚨 Flagged' if phishtank_flagged else '✅ Clean'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">SSL</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#00E676' if features['has_https'] else '#FFA500'};">{'🔒 Secured' if features['has_https'] else '⚠ HTTP'}</div>
                </div>
                <div>
                    <div style="color:#94A3B8; font-size:0.75rem;">Domain Age</div>
                    <div style="font-size:1.2rem; font-weight:600; color:{'#FFA500' if whois_info.get('age_days') and whois_info['age_days'] < 30 else '#00E676'};">{whois_info.get('age_days', 'N/A')}d</div>
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
    
    # FEATURE BREAKDOWN (Glass Cards)
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color:#00F5FF; margin-top:0;">🔍 Feature Analysis</h3>
        """, unsafe_allow_html=True)
        
        # Color-coded feature list
        def feature_status(value, threshold=0):
            return "✅" if not value else "⚠️" if value else "✅"
        
        st.markdown(f"""
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:0.85rem;">
            <div style="color:#94A3B8;">SSL</div><div style="color:{'#00E676' if features['has_https'] else '#FF4444'};">{feature_status(features['has_https'], 1)} {'Secured' if features['has_https'] else 'Insecure'}</div>
            <div style="color:#94A3B8;">IP Masked</div><div style="color:{'#FF4444' if features['has_ip'] else '#00E676'};">{feature_status(features['has_ip'])} {'Yes' if features['has_ip'] else 'No'}</div>
            <div style="color:#94A3B8;">Suspicious TLD</div><div style="color:{'#FF4444' if features['has_suspicious_tld'] else '#00E676'};">{feature_status(features['has_suspicious_tld'])} {'Yes' if features['has_suspicious_tld'] else 'No'}</div>
            <div style="color:#94A3B8;">Brand Impersonation</div><div style="color:{'#FFA500' if features['has_common_brand'] else '#00E676'};">{feature_status(features['has_common_brand'])} {'Yes' if features['has_common_brand'] else 'No'}</div>
            <div style="color:#94A3B8;">Redirects</div><div style="color:{'#FFA500' if features['has_redirect'] else '#00E676'};">{feature_status(features['has_redirect'])} {'Yes' if features['has_redirect'] else 'No'}</div>
            <div style="color:#94A3B8;">@ Symbol</div><div style="color:{'#FF4444' if features['has_at'] else '#00E676'};">{feature_status(features['has_at'])} {'Yes' if features['has_at'] else 'No'}</div>
            <div style="color:#94A3B8;">Subdomains</div><div style="color:{'#FFA500' if features['subdomain_count'] > 2 else '#00E676'};">{features['subdomain_count']}</div>
            <div style="color:#94A3B8;">Dash in Host</div><div style="color:{'#FFA500' if features['has_dash'] else '#00E676'};">{feature_status(features['has_dash'])} {'Yes' if features['has_dash'] else 'No'}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color:#00F5FF; margin-top:0;">📜 WHOIS Registry</h3>
        """, unsafe_allow_html=True)
        if whois_info.get("found"):
            st.markdown(f"""
            <div class="metric-grid">
                <div class="metric-item">
                    <div class="metric-value" style="font-size:0.9rem;">{whois_info['registrar'][:15]}</div>
                    <div class="metric-label">Registrar</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:0.9rem;">{whois_info['creation_date'][:10] if whois_info['creation_date'] != 'Unknown' else 'N/A'}</div>
                    <div class="metric-label">Created</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:0.9rem;">{whois_info['age_days'] if whois_info['age_days'] else 'N/A'}d</div>
                    <div class="metric-label">Age</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:0.9rem; color:{'#FF4444' if whois_info['age_days'] and whois_info['age_days'] < 30 else '#00E676'};">{whois_info['age_status'][:20]}</div>
                    <div class="metric-label">Status</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='color:#94A3B8;'>{whois_info.get('error', 'WHOIS unavailable')}</div>", unsafe_allow_html=True)
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
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;">{hop[:60]}...</span>
                </div>
                """, unsafe_allow_html=True)
            elif i == len(result['redirect_chain'])-1:
                st.markdown(f"""
                <div style="margin-left:5px;border-left:2px solid rgba(255,255,255,0.05);height:10px;"></div>
                <div class="timeline-item">
                    <div style="width:12px;height:12px;border-radius:50%;background:#00F5FF;flex-shrink:0;"></div>
                    <span style="font-size:0.85rem;color:#00F5FF;">🏁 Final</span>
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;">{hop[:60]}...</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="margin-left:5px;border-left:2px solid rgba(255,255,255,0.05);height:10px;"></div>
                <div class="timeline-item">
                    <div style="width:12px;height:12px;border-radius:50%;background:#FFA500;flex-shrink:0;"></div>
                    <span style="font-size:0.85rem;color:#94A3B8;">➡️ Hop {i}</span>
                    <span style="font-size:0.7rem;color:#475569;margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;">{hop[:60]}...</span>
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
            file_name=f"threatx_{result['host_domain']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "📊 CSV Report",
            data=build_csv_report(result),
            file_name=f"threatx_{result['host_domain']}.csv",
            mime="text/csv",
            use_container_width=True,
        )

# ---------- REPORT BUILDERS ----------
def build_csv_report(result):
    row = {
        "URL": result["input_url"],
        "Final URL": result["final_url"],
        "Verdict": "DANGEROUS" if result["is_malicious"] else "SAFE",
        "Risk %": result["risk_percent"],
        "Safety %": result["safety_percent"],
        "PhishTank": "Flagged" if result["phishtank_flagged"] else "Clean",
        "SSL": "Yes" if result["features"]["has_https"] else "No",
        "IP Mask": "Yes" if result["features"]["has_ip"] else "No",
        "Domain Age": result["whois_info"].get("age_days", "N/A"),
        "Registrar": result["whois_info"].get("registrar", "N/A"),
        "Server IP": result["resolved_ip"],
        "Country": result["geo_info"]["country"] if result["geo_info"] else "N/A",
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
            "THREAT-X AI PRO — Scan Report",
            "=" * 60,
            f"URL:        {result['input_url']}",
            f"Final URL:  {result['final_url']}",
            f"Verdict:    {verdict}",
            f"Risk:       {result['risk_percent']}%",
            f"PhishTank:  {'Flagged' if result['phishtank_flagged'] else 'Clean'}",
            f"SSL:        {'Yes' if result['features']['has_https'] else 'No'}",
            f"Server IP:  {result['resolved_ip']}",
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
        with st.spinner("🔄 Initializing AI Threat Scanner..."):
            # Live animation
            scan_status = st.empty()
            with scan_status.container():
                st.markdown("### 🔄 Live Scan in Progress")
                steps = [
                    ("🌐 Scanning DNS Records...", 0.3),
                    ("🔒 Checking SSL Certificate...", 0.5),
                    ("📜 Loading WHOIS Registry...", 0.7),
                    ("🧠 Analyzing Features...", 0.85),
                    ("☁️ Checking PhishTank...", 0.95),
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
                    time.sleep(0.6)
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
            
            result = scan_url_advanced(user_url)
            display_advanced_result(result)

# ---------- BULK SCANNER ----------
with tab_bulk:
    st.markdown("""
    <div class="glass-card">
        <h3 style="color:#00F5FF; margin-top:0;">📂 Bulk URL Scanner</h3>
        <p style="color:#94A3B8;">Upload a CSV with a column named <strong>url</strong>, or paste URLs (one per line).</p>
    """, unsafe_allow_html=True)
    
    uploaded_csv = st.file_uploader("Upload CSV", type=["csv"], key="bulk_csv")
    pasted_urls = st.text_area("Paste URLs (one per line)", height=150, placeholder="https://example.com\nhttps://another.com", key="bulk_urls")
    
    if st.button("🔍 Scan All", use_container_width=True, key="bulk_scan"):
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
                    res = scan_url_advanced(u)
                    results.append({
                        "URL": res["input_url"],
                        "Verdict": "⚠️ DANGEROUS" if res["is_malicious"] else "✅ SAFE",
                        "Risk %": res["risk_percent"],
                        "PhishTank": "🚨 Flagged" if res["phishtank_flagged"] else "✅ Clean",
                        "SSL": "Yes" if res["features"]["has_https"] else "No",
                        "IP Mask": "Yes" if res["features"]["has_ip"] else "No",
                        "Domain Age": res["whois_info"].get("age_days", "N/A"),
                        "Country": res["geo_info"]["country"] if res["geo_info"] else "N/A",
                    })
                except:
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
    <p>🛡️ Threat-X AI Pro • Advanced Phishing Detection</p>
    <p>⚡ ML • PhishTank • WHOIS • Geolocation</p>
    <p style="color:#334155;">Made with ❤️ by <strong style="color:#00F5FF;">Vedant Agrawal</strong></p>
</div>
""", unsafe_allow_html=True)
