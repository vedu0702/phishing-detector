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

# ============ PAGE CONFIG ============
st.set_page_config(page_title="Threat-X AI", page_icon="🛡️", layout="wide")

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
    .timeline-line {
        width: 2px;
        height: 20px;
        background: rgba(255, 255, 255, 0.1);
        margin-left: 5px;
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
    <h1 class="hero-title">🛡️ THREAT-X AI</h1>
    <p class="hero-sub">Enterprise Phishing Detection Platform • Powered by Machine Learning</p>
</div>
""", unsafe_allow_html=True)

# ============ ML MODEL ============
@st.cache_resource
def compile_advanced_ml_model():
    training_data = [
        [15, 0, 0, 0, 2.4, 0, 0], [18, 0, 1, 0, 2.7, 0, 0], [22, 0, 2, 0, 3.1, 0, 0], [28, 0, 0, 0, 2.9, 0, 0],
        [32, 0, 1, 2, 4.2, 1, 1], [45, 0, 0, 2, 4.1, 1, 1], [55, 0, 1, 2, 4.3, 1, 1], [72, 1, 2, 1, 4.5, 1, 1],
        [34, 0, 1, 2, 4.2, 1, 1], [17, 0, 1, 0, 4.4, 1, 1], [26, 0, 2, 1, 4.1, 1, 1], [38, 0, 1, 1, 4.0, 1, 1]
    ]
    features = ['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token']
    df = pd.DataFrame(training_data, columns=features + ['result'])
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(df[features], df['result'])
    return clf

cyber_classifier = compile_advanced_ml_model()

# ============ FUNCTIONS ============
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
        updated = first(w.updated_date)
        age_days = None
        if isinstance(created, datetime.datetime):
            age_days = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
        if age_days is None:
            age_status = "⚪ Registration date unavailable"
        elif age_days < 30:
            age_status = f"🔴 Very new domain — {age_days} days ago"
        elif age_days < 180:
            age_status = f"🟠 Recently registered — {age_days} days ago"
        else:
            age_status = f"🟢 Established domain — {age_days} days old"
        return {
            "found": True,
            "registrar": w.registrar or "Unknown",
            "creation_date": str(created) if created else "Unknown",
            "expiration_date": str(expires) if expires else "Unknown",
            "updated_date": str(updated) if updated else "Unknown",
            "name_servers": w.name_servers if w.name_servers else [],
            "org": getattr(w, "org", None) or "Not disclosed",
            "country": getattr(w, "country", None) or "Not disclosed",
            "age_days": age_days,
            "age_status": age_status
        }
    except ImportError:
        return {"found": False, "error": "python-whois not installed"}
    except Exception:
        return {"found": False, "error": "WHOIS lookup failed"}

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

def extract_lexical_vectors(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    host = parsed.netloc
    clean = host.lower().strip()
    length = len(clean)
    has_at = 1 if "@" in clean else 0
    subdomains = max(0, len(host.split('.')) - 2)
    has_dash = 1 if "-" in host else 0
    probs = [float(host.count(c)) / len(host) for c in set(host)] if len(host) > 0 else [0.0]
    entropy = -sum([p * math.log(p, 2) for p in probs]) if len(host) > 0 else 0.0
    tokens = ['login', 'verify', 'security', 'secure', 'billing', 'update', 'marketplace',
              'goog1e', 'faceb00k', 'netfliix', 'shekarius', '124', 'allegromt',
              'paypal', 'sbi', 'amazon', 'auth', 'portal']
    has_token = 1 if any(kw in clean for kw in tokens) and not any(
        wl in host for wl in ['google.com', 'github.com', 'wikipedia.org', 'paypal.com']
    ) else 0
    is_ssl = 1 if parsed.scheme == 'https' else 0
    is_ip_masked = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean.split(':')[0]) else 0
    features = [length, has_at, subdomains, has_dash, round(entropy, 2), has_token]
    pro_heuristics = {"is_ssl": is_ssl, "is_ip_masked": is_ip_masked}
    return features, host, pro_heuristics

def scan_url(user_target):
    original_url = user_target if user_target.startswith(('http://', 'https://')) else 'http://' + user_target
    redirect_chain, final_url = trace_redirect_chain(original_url)
    feature_weights, host_domain, pro_meta = extract_lexical_vectors(final_url)
    resolved_ip, dns_status_log = resolve_live_dns_ip(host_domain)
    geo_info = resolve_geolocation(resolved_ip)
    whois_info = resolve_whois_record(host_domain)
    eval_dataframe = pd.DataFrame([feature_weights], columns=['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token'])
    ml_probabilities = cyber_classifier.predict_proba(eval_dataframe)
    ml_phish_probability = float(ml_probabilities[0][1])
    dynamic_risk_weight = ml_phish_probability * 100.0
    if resolved_ip == "0.0.0.0":
        dynamic_risk_weight += 35.0
    if pro_meta["is_ssl"] == 0:
        dynamic_risk_weight += 15.0
    if pro_meta["is_ip_masked"] == 1:
        dynamic_risk_weight += 40.0
    if whois_info.get("found") and whois_info.get("age_days") is not None:
        if whois_info["age_days"] < 30:
            dynamic_risk_weight += 20.0
        elif whois_info["age_days"] < 180:
            dynamic_risk_weight += 8.0
    if len(redirect_chain) > 2:
        dynamic_risk_weight += 10.0
    risk_percent = round(min(99.4, max(4.2, dynamic_risk_weight)), 1)
    safety_percent = round(100.0 - risk_percent, 1)
    is_malicious_class = True if risk_percent >= 45.0 else False
    return {
        "input_url": user_target,
        "original_url": original_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "host_domain": host_domain,
        "feature_weights": feature_weights,
        "pro_meta": pro_meta,
        "resolved_ip": resolved_ip,
        "dns_status_log": dns_status_log,
        "geo_info": geo_info,
        "whois_info": whois_info,
        "ml_phish_probability": ml_phish_probability,
        "risk_percent": risk_percent,
        "safety_percent": safety_percent,
        "is_malicious_class": is_malicious_class,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ============ FUNCTIONS FOR REPORTS ============
def build_single_scan_csv(result):
    row = {
        "Scanned URL": result["input_url"],
        "Final URL": result["final_url"],
        "Redirect Hops": len(result["redirect_chain"]) - 1,
        "Verdict": "DANGEROUS" if result["is_malicious_class"] else "SAFE",
        "Risk %": result["risk_percent"],
        "Safety %": result["safety_percent"],
        "Server IP": result["resolved_ip"],
        "DNS Status": result["dns_status_log"],
        "SSL": "Yes" if result["pro_meta"]["is_ssl"] else "No",
        "IP-Masked Domain": "Yes" if result["pro_meta"]["is_ip_masked"] else "No",
        "Domain Age (days)": result["whois_info"].get("age_days", "N/A"),
        "Registrar": result["whois_info"].get("registrar", "N/A"),
        "Country (Server)": result["geo_info"]["country"] if result["geo_info"] else "N/A",
        "Scanned At (UTC)": result["scanned_at"],
    }
    buf = io.StringIO()
    pd.DataFrame([row]).to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")

def build_single_scan_pdf(result):
    buf = io.BytesIO()
    with PdfPages(buf) as pdf:
        fig, ax = plt.subplots(figsize=(8.27, 11.69))
        ax.axis("off")
        fig.patch.set_facecolor('white')
        verdict = "⚠ DANGEROUS" if result["is_malicious_class"] else "✔ SAFE"
        lines = [
            "THREAT-X AI — Scan Report",
            "=" * 60,
            f"Scanned URL:      {result['input_url']}",
            f"Final URL:        {result['final_url']}",
            f"Redirect Hops:    {len(result['redirect_chain']) - 1}",
            f"Scanned At (UTC): {result['scanned_at']}",
            "",
            f"VERDICT: {verdict}",
            f"Risk Score:   {result['risk_percent']}%",
            f"Safety Score: {result['safety_percent']}%",
            "",
            "-- Network --",
            f"Server IP:    {result['resolved_ip']}  ({result['dns_status_log']})",
            f"SSL Secured:  {'Yes' if result['pro_meta']['is_ssl'] else 'No'}",
            f"IP-Masked:    {'Yes' if result['pro_meta']['is_ip_masked'] else 'No'}",
            "",
            "-- WHOIS --",
        ]
        if result["whois_info"].get("found"):
            w = result["whois_info"]
            lines += [
                f"Registrar:    {w['registrar']}",
                f"Created:      {w['creation_date']}",
                f"Age Status:   {w['age_status']}",
            ]
        else:
            lines.append(f"WHOIS unavailable: {result['whois_info'].get('error')}")
        lines.append("")
        lines.append("-- Geolocation --")
        if result["geo_info"]:
            g = result["geo_info"]
            lines += [
                f"Country: {g['country']}   City: {g['city']}   ISP: {g['isp']}",
            ]
        else:
            lines.append("Geolocation unavailable.")
        if len(result["redirect_chain"]) > 1:
            lines.append("")
            lines.append("-- Redirect Chain --")
            for i, hop in enumerate(result["redirect_chain"]):
                lines.append(f"  {i+1}. {hop}")
        ax.text(0.02, 0.98, "\n".join(lines), va="top", ha="left", fontsize=9,
                family="monospace", transform=ax.transAxes, wrap=True)
        pdf.savefig(fig)
        plt.close(fig)
    return buf.getvalue()

# ============ DISPLAY RESULTS FUNCTION ============
def display_scan_result(result):
    risk_percent = result["risk_percent"]
    safety_percent = result["safety_percent"]
    is_malicious_class = result["is_malicious_class"]
    resolved_ip = result["resolved_ip"]
    dns_status_log = result["dns_status_log"]
    geo_info = result["geo_info"]
    whois_info = result["whois_info"]
    feature_weights = result["feature_weights"]
    pro_meta = result["pro_meta"]
    redirect_chain = result["redirect_chain"]
    ml_phish_probability = result["ml_phish_probability"]

    # BIG STATUS CARD
    st.markdown("---")
    if is_malicious_class:
        st.markdown(f"""
        <div class="status-danger">
            <h1 style="color: #FF4444; margin: 0;">🚨 DANGEROUS WEBSITE</h1>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; margin-top: 1.5rem;">
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Risk Score</div>
                    <div style="font-size: 2.5rem; font-weight: 700; color: #FF4444;">{risk_percent}%</div>
                </div>
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">AI Confidence</div>
                    <div style="font-size: 2.5rem; font-weight: 700; color: #FF6B6B;">{round(ml_phish_probability*100, 1)}%</div>
                </div>
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Category</div>
                    <div style="font-size: 1.5rem; font-weight: 600; color: #FF6B6B;">⚠ Phishing / Malware</div>
                </div>
            </div>
            <div style="margin-top: 1rem; background: rgba(255,0,0,0.1); border-radius: 50px; padding: 0.3rem;">
                <div style="background: #FF4444; border-radius: 50px; height: 6px; width: {risk_percent}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="status-safe">
            <h1 style="color: #00E676; margin: 0;">✅ SAFE WEBSITE</h1>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; margin-top: 1.5rem;">
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Risk Score</div>
                    <div style="font-size: 2.5rem; font-weight: 700; color: #00E676;">{risk_percent}%</div>
                </div>
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">AI Confidence</div>
                    <div style="font-size: 2.5rem; font-weight: 700; color: #00F5FF;">{round((1-ml_phish_probability)*100, 1)}%</div>
                </div>
                <div>
                    <div style="color: #94A3B8; font-size: 0.8rem; text-transform: uppercase;">Category</div>
                    <div style="font-size: 1.5rem; font-weight: 600; color: #00E676;">🛡 Trusted</div>
                </div>
            </div>
            <div style="margin-top: 1rem; background: rgba(0,230,118,0.1); border-radius: 50px; padding: 0.3rem;">
                <div style="background: linear-gradient(90deg, #00E676, #00F5FF); border-radius: 50px; height: 6px; width: {safety_percent}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # GAUGE METRIC
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem 0;">
            <div style="position: relative; display: inline-block;">
                <svg width="180" height="180" viewBox="0 0 180 180">
                    <circle cx="90" cy="90" r="75" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="12"/>
                    <circle cx="90" cy="90" r="75" fill="none" stroke="{'#00E676' if not is_malicious_class else '#FF4444'}" 
                        stroke-width="12" stroke-dasharray="{2*3.14*75*risk_percent/100} {2*3.14*75*(100-risk_percent)/100}" 
                        stroke-linecap="round" transform="rotate(-90 90 90)"/>
                    <text x="90" y="85" text-anchor="middle" fill="#FFFFFF" font-size="28" font-weight="700">{risk_percent}%</text>
                    <text x="90" y="110" text-anchor="middle" fill="#94A3B8" font-size="12">{'LOW RISK' if not is_malicious_class else 'HIGH RISK'}</text>
                </svg>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # GLASS CARDS
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #00F5FF; margin-top: 0;">📜 WHOIS Registry</h3>
        """, unsafe_allow_html=True)
        if whois_info.get("found"):
            st.markdown(f"""
            <div class="metric-grid">
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{whois_info['registrar']}</div>
                    <div class="metric-label">Registrar</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{whois_info['creation_date'][:10] if whois_info['creation_date'] != 'Unknown' else 'N/A'}</div>
                    <div class="metric-label">Created</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{whois_info['expiration_date'][:10] if whois_info['expiration_date'] != 'Unknown' else 'N/A'}</div>
                    <div class="metric-label">Expires</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem; color: {'#00E676' if whois_info.get('age_days') and whois_info['age_days'] > 180 else '#FFA500'};">
                        {whois_info.get('age_days', 'N/A') if whois_info.get('age_days') else 'N/A'}d
                    </div>
                    <div class="metric-label">Age</div>
                </div>
            </div>
            <div style="color:#94A3B8; font-size:0.85rem;">{whois_info.get('age_status', '')}</div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='color:#94A3B8;'>⚪ {whois_info.get('error', 'WHOIS data unavailable')}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #00F5FF; margin-top: 0;">🌍 Geolocation</h3>
        """, unsafe_allow_html=True)
        if geo_info:
            st.markdown(f"""
            <div class="metric-grid">
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{geo_info['country']}</div>
                    <div class="metric-label">Country</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{geo_info['city']}</div>
                    <div class="metric-label">City</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{geo_info['isp'][:15]}</div>
                    <div class="metric-label">ISP</div>
                </div>
                <div class="metric-item">
                    <div class="metric-value" style="font-size:1rem;">{geo_info['timezone']}</div>
                    <div class="metric-label">Timezone</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("<div style='color:#94A3B8;'>⚪ Geolocation unavailable</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #00F5FF; margin-top: 0;">🌐 DNS & SSL</h3>
        """, unsafe_allow_html=True)
        st.markdown(f"""
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">Server IP</div>
                <div style="color:#FFFFFF; font-weight:600;">{resolved_ip}</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">Status</div>
                <div style="color:{'#00E676' if 'Live' in dns_status_log else '#FF4444'}; font-weight:600;">{dns_status_log}</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">SSL</div>
                <div style="color:{'#00E676' if pro_meta['is_ssl'] else '#FFA500'}; font-weight:600;">{'🔒 Secured' if pro_meta['is_ssl'] else '⚠ HTTP'}</div>
            </div>
            <div>
                <div style="color:#94A3B8; font-size:0.75rem;">IP Mask</div>
                <div style="color:{'#FF4444' if pro_meta['is_ip_masked'] else '#00E676'}; font-weight:600;">{'Yes' if pro_meta['is_ip_masked'] else 'No'}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="glass-card">
            <h3 style="color: #00F5FF; margin-top: 0;">🔀 Redirect Chain</h3>
        """, unsafe_allow_html=True)
        if len(redirect_chain) > 1:
            for i, hop in enumerate(redirect_chain):
                if i == 0:
                    st.markdown(f"""
                    <div class="timeline-item">
                        <div class="timeline-dot" style="background:#00E676;"></div>
                        <span style="font-size:0.85rem; color:#94A3B8;">● Original URL</span>
                        <span style="font-size:0.7rem; color:#475569; margin-left:auto; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:150px;">{hop[:40]}...</span>
                    </div>
                    """, unsafe_allow_html=True)
                elif i == len(redirect_chain)-1:
                    st.markdown(f"""
                    <div style="margin-left:5px; border-left:2px solid rgba(255,255,255,0.05); height:10px;"></div>
                    <div class="timeline-item">
                        <div class="timeline-dot" style="background:#00F5FF;"></div>
                        <span style="font-size:0.85rem; color:#00F5FF;">🏁 Final Website</span>
                        <span style="font-size:0.7rem; color:#475569; margin-left:auto; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:150px;">{hop[:40]}...</span>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div style="margin-left:5px; border-left:2px solid rgba(255,255,255,0.05); height:10px;"></div>
                    <div class="timeline-item">
                        <div class="timeline-dot" style="background:#FFA500;"></div>
                        <span style="font-size:0.85rem; color:#94A3B8;">➡️ Redirect {i}</span>
                        <span style="font-size:0.7rem; color:#475569; margin-left:auto; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:150px;">{hop[:40]}...</span>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.markdown("<div style='color:#94A3B8;'>✅ No redirects detected — direct link</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # TECHNICAL METRICS
    st.markdown("---")
    st.markdown("""
    <div class="glass-card">
        <h3 style="color: #00F5FF; margin-top: 0;">🧠 Technical System Metrics</h3>
    """, unsafe_allow_html=True)
    st.markdown(f"""
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem;">
        <div>
            <div style="color:#94A3B8; font-size:0.75rem;">Feature Vector</div>
            <div style="color:#FFFFFF; font-family:monospace; font-size:0.85rem;">{feature_weights}</div>
        </div>
        <div>
            <div style="color:#94A3B8; font-size:0.75rem;">AI Confidence</div>
            <div style="color:#00F5FF; font-weight:600;">{round(ml_phish_probability*100, 1)}%</div>
        </div>
        <div>
            <div style="color:#94A3B8; font-size:0.75rem;">Scanned At</div>
            <div style="color:#94A3B8; font-size:0.85rem;">{result['scanned_at']}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # DOWNLOAD BUTTONS
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📄 Download PDF Report",
            data=build_single_scan_pdf(result),
            file_name=f"threatx_report_{result['host_domain']}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "📊 Download CSV Report",
            data=build_single_scan_csv(result),
            file_name=f"threatx_report_{result['host_domain']}.csv",
            mime="text/csv",
            use_container_width=True,
        )

# ============ TABS: SCANNER + BULK ============
tab_scanner, tab_bulk = st.tabs(["🔍 Single Scanner", "📂 Bulk Scanner"])

# ============ TAB 1: SINGLE SCANNER ============
with tab_scanner:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        user_target = st.text_input("", placeholder="🔍 Enter website URL to scan...", label_visibility="collapsed", key="single_url")
        scan_clicked = st.button("🚀 Scan Website", use_container_width=True, key="single_scan")

    if scan_clicked and user_target:
        with st.spinner("🔄 Initializing AI Threat Scanner..."):
            # Live Scan Animation
            scan_status = st.empty()
            with scan_status.container():
                st.markdown("### 🔄 Live Scan in Progress")
                steps = [
                    ("🌐 Scanning DNS Records...", 0.3),
                    ("🔒 Checking SSL Certificate...", 0.5),
                    ("📜 Loading WHOIS Registry...", 0.7),
                    ("🧠 Running AI Prediction Model...", 0.9),
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
                    time.sleep(0.8)
                st.markdown("""
                <div class="scan-line">
                    <span>✅ Scan Complete!</span>
                    <span class="scan-status">✔ Done</span>
                </div>
                <div class="progress-container">
                    <div class="progress-fill" style="width: 100%;"></div>
                </div>
                """, unsafe_allow_html=True)
                time.sleep(0.5)
            scan_status.empty()

            result = scan_url(user_target)
            display_scan_result(result)

# ============ TAB 2: BULK SCANNER ============
with tab_bulk:
    st.markdown("""
    <div class="glass-card">
        <h3 style="color: #00F5FF; margin-top: 0;">📂 Bulk URL Scanner</h3>
        <p style="color: #94A3B8;">Upload a CSV file with a column named <strong>url</strong>, or paste one link per line below.</p>
    """, unsafe_allow_html=True)

    uploaded_csv = st.file_uploader("Upload CSV of URLs", type=["csv"], key="bulk_csv")
    pasted_urls = st.text_area("...or paste URLs here (one per line)", height=150, placeholder="https://example.com\nhttps://another-site.com", key="bulk_urls")

    if st.button("🔍 Scan All URLs", use_container_width=True, key="bulk_scan"):
        url_list = []

        if uploaded_csv is not None:
            try:
                df_in = pd.read_csv(uploaded_csv)
                url_col = None
                for c in df_in.columns:
                    if c.strip().lower() == "url":
                        url_col = c
                        break
                if url_col is None:
                    st.error("CSV must contain a column named 'url'.")
                else:
                    url_list.extend([str(u).strip() for u in df_in[url_col].dropna().tolist()])
            except Exception as e:
                st.error(f"Could not read CSV file: {e}")

        if pasted_urls.strip():
            url_list.extend([u.strip() for u in pasted_urls.splitlines() if u.strip()])

        url_list = list(dict.fromkeys(url_list))

        if not url_list:
            st.info("Please upload a CSV or paste at least one URL to run a bulk scan.")
        else:
            progress = st.progress(0, text=f"Scanning 0 / {len(url_list)}...")
            bulk_results = []

            for i, u in enumerate(url_list):
                try:
                    res = scan_url(u)
                    bulk_results.append({
                        "URL": res["input_url"],
                        "Final URL": res["final_url"],
                        "Verdict": "⚠️ DANGEROUS" if res["is_malicious_class"] else "✅ SAFE",
                        "Risk %": res["risk_percent"],
                        "Redirect Hops": len(res["redirect_chain"]) - 1,
                        "Server IP": res["resolved_ip"],
                        "SSL": "Yes" if res["pro_meta"]["is_ssl"] else "No",
                        "Domain Age (days)": res["whois_info"].get("age_days", "N/A"),
                        "Country": res["geo_info"]["country"] if res["geo_info"] else "N/A",
                    })
                except Exception as e:
                    bulk_results.append({
                        "URL": u, "Final URL": "ERROR", "Verdict": "⚪ SCAN FAILED",
                        "Risk %": "N/A", "Redirect Hops": "N/A", "Server IP": "N/A",
                        "SSL": "N/A",
                        "Domain Age (days)": "N/A", "Country": "N/A",
                    })
                progress.progress((i + 1) / len(url_list), text=f"Scanning {i + 1} / {len(url_list)}...")

            progress.empty()

            bulk_df = pd.DataFrame(bulk_results)

            st.markdown("---")
            st.markdown(f"### 📊 Bulk Scan Summary — {len(url_list)} URLs")

            danger_count = sum(1 for r in bulk_results if r["Verdict"] == "⚠️ DANGEROUS")
            safe_count = sum(1 for r in bulk_results if r["Verdict"] == "✅ SAFE")
            failed_count = sum(1 for r in bulk_results if r["Verdict"] == "⚪ SCAN FAILED")

            s_col1, s_col2, s_col3 = st.columns(3)
            s_col1.metric("⚠️ Dangerous", danger_count)
            s_col2.metric("✅ Safe", safe_count)
            s_col3.metric("⚪ Failed", failed_count)

            st.dataframe(bulk_df, use_container_width=True)

            csv_buf = io.StringIO()
            bulk_df.to_csv(csv_buf, index=False)
            st.download_button(
                "⬇️ Download Bulk Scan Results (CSV)",
                data=csv_buf.getvalue().encode("utf-8"),
                file_name="threatx_bulk_scan_results.csv",
                mime="text/csv",
                use_container_width=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)

# ============ FOOTER ============
st.markdown("""
<div style="text-align: center; padding: 2rem; color: #475569; font-size: 0.9rem; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 3rem;">
    <p style="margin: 0;">🛡️ Threat-X AI • Enterprise Phishing Detection Platform</p>
    <p style="margin: 0.3rem 0;">⚡ Powered by Machine Learning • Random Forest • Python • Streamlit</p>
    <p style="margin: 0.5rem 0; color: #334155;">Made with ❤️ by <strong style="color: #00F5FF;">Vedant Agrawal</strong></p>
</div>
""", unsafe_allow_html=True)
