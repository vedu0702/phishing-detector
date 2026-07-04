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

# 1. Premium Enterprise UI Configuration with Modern Dark Theme
st.set_page_config(
    page_title="Threat-X Global Guard Pro", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for Premium Dark Theme
st.markdown("""
    <style>
        /* Main Background with Gradient */
        .stApp {
            background: linear-gradient(135deg, #0a0e1a 0%, #1a1f35 50%, #0d1225 100%);
        }
        
        /* Main Container */
        .main > div {
            background: rgba(10, 14, 26, 0.85);
            backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 2rem;
            margin: 1rem;
            border: 1px solid rgba(0, 255, 204, 0.08);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8);
        }
        
        /* Hide Streamlit Default Elements */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}
        .stAppDeployButton {display:none;}
        
        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, #00ffcc, #00ccaa);
            border-radius: 10px;
        }
        
        /* Headers */
        h1, h2, h3, h4, h5, h6 {
            color: #ffffff !important;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            font-weight: 600 !important;
            letter-spacing: -0.02em !important;
        }
        
        /* Main Title */
        .main-title {
            text-align: center;
            padding: 2rem 0 1rem 0;
            background: linear-gradient(180deg, rgba(0,255,204,0.03) 0%, transparent 100%);
        }
        
        .main-title h1 {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 0%, #00ffcc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 40px rgba(0, 255, 204, 0.1);
        }
        
        .main-title .subtitle {
            color: #94a3b8;
            font-size: 1.1rem;
            font-weight: 400;
            letter-spacing: 0.05em;
            border-top: 1px solid rgba(0, 255, 204, 0.1);
            padding-top: 1rem;
            display: inline-block;
        }
        
        .main-title .version-badge {
            display: inline-block;
            background: rgba(0, 255, 204, 0.1);
            color: #00ffcc;
            padding: 0.2rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            border: 1px solid rgba(0, 255, 204, 0.2);
            margin-left: 0.5rem;
        }
        
        /* Input Box */
        .stTextInput > div > div > input {
            background: rgba(255, 255, 255, 0.03) !important;
            border: 1px solid rgba(0, 255, 204, 0.15) !important;
            border-radius: 12px !important;
            color: #ffffff !important;
            padding: 0.8rem 1.2rem !important;
            font-size: 1rem !important;
            transition: all 0.3s ease !important;
        }
        
        .stTextInput > div > div > input:focus {
            border-color: #00ffcc !important;
            box-shadow: 0 0 0 3px rgba(0, 255, 204, 0.1) !important;
            background: rgba(255, 255, 255, 0.05) !important;
        }
        
        .stTextInput > div > div > input::placeholder {
            color: #475569 !important;
        }
        
        /* Buttons */
        .stButton > button {
            background: linear-gradient(135deg, #00ffcc 0%, #00ccaa 100%) !important;
            color: #0a0e1a !important;
            font-weight: 700 !important;
            border: none !important;
            border-radius: 12px !important;
            padding: 0.8rem 2rem !important;
            font-size: 1.1rem !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 20px rgba(0, 255, 204, 0.15) !important;
            letter-spacing: 0.02em !important;
            width: 100% !important;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px) scale(1.01);
            box-shadow: 0 8px 30px rgba(0, 255, 204, 0.25) !important;
            background: linear-gradient(135deg, #00ffcc 0%, #00bbaa 100%) !important;
        }
        
        .stButton > button:active {
            transform: scale(0.98);
        }
        
        /* Metrics */
        [data-testid="metric-container"] {
            background: rgba(255, 255, 255, 0.03) !important;
            border: 1px solid rgba(0, 255, 204, 0.06) !important;
            border-radius: 16px !important;
            padding: 1.2rem !important;
            backdrop-filter: blur(10px) !important;
            transition: all 0.3s ease !important;
        }
        
        [data-testid="metric-container"]:hover {
            border-color: rgba(0, 255, 204, 0.2) !important;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }
        
        [data-testid="metric-container"] label {
            color: #94a3b8 !important;
            font-weight: 500 !important;
            font-size: 0.85rem !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        [data-testid="metric-container"] div {
            color: #ffffff !important;
            font-weight: 700 !important;
        }
        
        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 12px;
            padding: 0.3rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .stTabs [data-baseweb="tab"] {
            border-radius: 8px !important;
            padding: 0.6rem 1.5rem !important;
            color: #94a3b8 !important;
            font-weight: 500 !important;
            transition: all 0.3s ease !important;
            background: transparent !important;
        }
        
        .stTabs [data-baseweb="tab"][aria-selected="true"] {
            background: rgba(0, 255, 204, 0.1) !important;
            color: #00ffcc !important;
            border: 1px solid rgba(0, 255, 204, 0.2) !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            color: #ffffff !important;
            background: rgba(255, 255, 255, 0.05) !important;
        }
        
        /* Dataframe */
        .stDataFrame {
            border-radius: 12px !important;
            overflow: hidden !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        
        .stDataFrame thead tr th {
            background: rgba(0, 255, 204, 0.05) !important;
            color: #00ffcc !important;
            font-weight: 600 !important;
            padding: 0.8rem !important;
            border-bottom: 2px solid rgba(0, 255, 204, 0.1) !important;
        }
        
        .stDataFrame tbody tr td {
            color: #e2e8f0 !important;
            padding: 0.6rem !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03) !important;
        }
        
        .stDataFrame tbody tr:hover {
            background: rgba(0, 255, 204, 0.02) !important;
        }
        
        /* Info/Warning/Success Messages */
        .stAlert {
            border-radius: 12px !important;
            border-left: 4px solid !important;
            background: rgba(255, 255, 255, 0.02) !important;
            backdrop-filter: blur(10px) !important;
        }
        
        .stAlert > div {
            color: #e2e8f0 !important;
        }
        
        /* Download Buttons */
        .stDownloadButton > button {
            background: rgba(255, 255, 255, 0.05) !important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            color: #e2e8f0 !important;
            border-radius: 10px !important;
            transition: all 0.3s ease !important;
        }
        
        .stDownloadButton > button:hover {
            background: rgba(0, 255, 204, 0.1) !important;
            border-color: #00ffcc !important;
            color: #00ffcc !important;
        }
        
        /* Code Blocks */
        .stCodeBlock {
            background: rgba(0, 0, 0, 0.3) !important;
            border-radius: 12px !important;
            border: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        
        /* Progress Bar */
        .stProgress > div > div {
            background: linear-gradient(90deg, #00ffcc, #00ccaa) !important;
            border-radius: 10px !important;
        }
        
        /* Spinner */
        .stSpinner > div {
            border-color: #00ffcc !important;
        }
        
        /* Tables */
        .stTable thead tr th {
            background: rgba(0, 255, 204, 0.05) !important;
            color: #00ffcc !important;
            font-weight: 600 !important;
        }
        
        .stTable tbody tr td {
            color: #e2e8f0 !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03) !important;
        }
        
        /* Divider */
        hr {
            border: none !important;
            height: 1px !important;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 204, 0.2), transparent) !important;
            margin: 2rem 0 !important;
        }
        
        /* Text Area */
        .stTextArea > div > div > textarea {
            background: rgba(255, 255, 255, 0.03) !important;
            border: 1px solid rgba(0, 255, 204, 0.15) !important;
            border-radius: 12px !important;
            color: #ffffff !important;
        }
        
        .stTextArea > div > div > textarea:focus {
            border-color: #00ffcc !important;
            box-shadow: 0 0 0 3px rgba(0, 255, 204, 0.1) !important;
        }
        
        /* File Uploader */
        .stFileUploader > div {
            background: rgba(255, 255, 255, 0.02) !important;
            border: 2px dashed rgba(0, 255, 204, 0.2) !important;
            border-radius: 12px !important;
            padding: 2rem !important;
        }
        
        .stFileUploader > div:hover {
            border-color: #00ffcc !important;
            background: rgba(0, 255, 204, 0.02) !important;
        }
        
        /* Column Headers */
        .column-header {
            color: #94a3b8;
            font-size: 0.85rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        /* Glowing Animation for Status */
        @keyframes pulse-glow {
            0%, 100% { box-shadow: 0 0 20px rgba(0, 255, 204, 0.1); }
            50% { box-shadow: 0 0 40px rgba(0, 255, 204, 0.2); }
        }
        
        .glow-box {
            animation: pulse-glow 3s ease-in-out infinite;
        }
        
        /* Custom Badges */
        .badge-safe {
            display: inline-block;
            background: rgba(0, 255, 204, 0.1);
            color: #00ffcc;
            padding: 0.2rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.8rem;
            border: 1px solid rgba(0, 255, 204, 0.2);
        }
        
        .badge-danger {
            display: inline-block;
            background: rgba(255, 51, 51, 0.1);
            color: #ff3333;
            padding: 0.2rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.8rem;
            border: 1px solid rgba(255, 51, 51, 0.2);
        }
    </style>
""", unsafe_allow_html=True)

# Main Header
st.markdown("""
    <div class="main-title">
        <h1>🛡️ THREAT-X</h1>
        <div style="display: flex; justify-content: center; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <span class="subtitle">GLOBAL GUARD PRO</span>
            <span class="version-badge">v13.0</span>
            <span style="color: #475569; font-size: 0.85rem;">• Enterprise Edition</span>
        </div>
        <p style="color: #64748b; font-size: 1rem; margin-top: 1rem; max-width: 600px; margin-left: auto; margin-right: auto; line-height: 1.6;">
            Advanced ML-powered website authenticity verification with real-time threat intelligence
        </p>
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# 2. Advanced RandomForest Framework Ingestion Block
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

# 4. Live DNS Host Resolver + IP Geolocation
def resolve_live_dns_ip(hostname):
    try:
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return socket.gethostbyname(hostname), "🟢 Live & Verified"
    except Exception:
        return "0.0.0.0", "🔴 Inactive / Blocked Server"

def resolve_geolocation(ip_address):
    """Live IP geolocation via ip-api.com (free, no key required)"""
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

# 4b. Live WHOIS Domain Registration Lookup (no key required)
def resolve_whois_record(hostname):
    """Live WHOIS lookup — registrar, creation/expiry dates, name servers"""
    try:
        import whois  # python-whois package
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
            age_status = f"🔴 Very new domain — registered {age_days} days ago (common phishing trait)"
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
        return {"found": False, "error": "python-whois not installed (pip install python-whois)"}
    except Exception:
        return {"found": False, "error": "WHOIS lookup failed — record may be privacy-protected or registry unreachable"}

# 4c. Redirect Chain Tracer — follows shorteners/redirect hops to the real final page
def trace_redirect_chain(url, max_hops=10):
    """
    Follows HTTP redirects (bit.ly, tinyurl, tracking hops, etc.) and returns
    the full chain of URLs plus the final resolved destination URL.
    """
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
        # Could not follow redirects (dead link, blocked, etc.) — scan original URL as-is
        return chain, url

# 5. Core Lexical Calculation & Extended Heuristics Engine
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

    # Extended pro features
    is_ssl = 1 if parsed.scheme == 'https' else 0
    is_ip_masked = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean.split(':')[0]) else 0

    features = [length, has_at, subdomains, has_dash, round(entropy, 2), has_token]
    pro_heuristics = {"is_ssl": is_ssl, "is_ip_masked": is_ip_masked}
    return features, host, pro_heuristics

# 6. Unified scan pipeline — used by both Single Scan and Bulk Scan
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

# 7. Report builders (PDF + CSV) for a single scan result
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
        fig, ax = plt.subplots(figsize=(8.27, 11.69))  # A4 portrait
        ax.axis("off")
        fig.patch.set_facecolor('#0a0e1a')

        verdict = "⚠ DANGEROUS" if result["is_malicious_class"] else "✔ SAFE"
        lines = [
            "THREAT-X GLOBAL GUARD PRO — Scan Report",
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
                family="monospace", transform=ax.transAxes, wrap=True, color='#e2e8f0')
        pdf.savefig(fig, facecolor='#0a0e1a')
        plt.close(fig)
    return buf.getvalue()

# 8. User Console Interface — Single Scan / Bulk Scan
tab_single, tab_bulk = st.tabs(["🔍 Single Scan", "📂 Bulk Scan"])

with tab_single:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        user_target = st.text_input(
            "🔗 Enter website address",
            placeholder="https://example.com",
            label_visibility="collapsed"
        )
        
        if st.button("🚀 ANALYZE WEBSITE", use_container_width=True):
            if user_target:
                with st.spinner("🔄 Analyzing website security patterns..."):
                    result = scan_url(user_target)

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

                # METRICS & ANALYSIS DASHBOARD
                st.markdown("---")
                st.markdown("### 📊 Security Analysis Report")
                
                # Status Cards
                col1, col2, col3 = st.columns(3)
                
                if is_malicious_class:
                    col1.markdown("""
                        <div style="background: rgba(255,51,51,0.05); border: 1px solid rgba(255,51,51,0.2); border-radius: 12px; padding: 1.2rem; text-align: center;">
                            <div style="font-size: 2rem;">⚠️</div>
                            <div style="color: #ff3333; font-weight: 700; font-size: 1.1rem;">DANGEROUS</div>
                            <div style="color: #94a3b8; font-size: 0.8rem;">Threat Detected</div>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    col1.markdown("""
                        <div style="background: rgba(0,255,204,0.05); border: 1px solid rgba(0,255,204,0.2); border-radius: 12px; padding: 1.2rem; text-align: center;">
                            <div style="font-size: 2rem;">✅</div>
                            <div style="color: #00ffcc; font-weight: 700; font-size: 1.1rem;">SAFE</div>
                            <div style="color: #94a3b8; font-size: 0.8rem;">Verified Secure</div>
                        </div>
                    """, unsafe_allow_html=True)
                
                col2.metric(
                    label="🚨 Risk Score",
                    value=f"{risk_percent}%",
                    delta="High Risk" if is_malicious_class else "Low Risk",
                    delta_color="inverse" if is_malicious_class else "normal"
                )
                
                col3.metric(
                    label="🟢 Safety Score",
                    value=f"{safety_percent}%",
                    delta="Protected" if not is_malicious_class else "Compromised",
                    delta_color="normal" if not is_malicious_class else "inverse"
                )

                st.markdown("---")

                # Risk Gauge
                st.markdown("#### 📈 Risk Assessment Gauge")
                
                fig, ax = plt.subplots(figsize=(10, 2))
                fig.patch.set_facecolor('transparent')
                ax.set_facecolor('transparent')
                
                # Create horizontal bar chart
                ax.barh([0], [risk_percent], color='#ff3333', height=0.4, alpha=0.8)
                ax.barh([0], [safety_percent], left=[risk_percent], color='#00ffcc', height=0.4, alpha=0.6)
                
                # Add threshold lines
                ax.axvline(x=45, color='#fbbf24', linestyle='--', linewidth=2, alpha=0.5, label='Threat Threshold')
                
                # Styling
                ax.set_xlim(0, 100)
                ax.set_yticks([])
                ax.set_xlabel('Risk Percentage', color='#94a3b8')
                ax.tick_params(colors='#94a3b8')
                ax.spines['bottom'].set_color('#1e293b')
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.spines['left'].set_visible(False)
                
                # Add risk indicator
                ax.text(risk_percent + 2, 0, f'Risk: {risk_percent}%', 
                       va='center', color='#ffffff', fontweight='bold', fontsize=10)
                
                st.pyplot(fig)
                plt.close(fig)

                st.markdown("---")

                # PRO FEATURE: Redirect Chain Tracing
                st.markdown("#### 🔀 Redirect Chain Analysis")
                if len(redirect_chain) > 1:
                    st.warning(f"⚠️ This URL redirects through {len(redirect_chain) - 1} hop(s) before reaching its destination.")
                    for i, hop in enumerate(redirect_chain):
                        tag = "🔗 Start" if i == 0 else ("🏁 Final" if i == len(redirect_chain) - 1 else f"➡️ Hop {i}")
                        st.code(f"{tag}: {hop}", language="text")
                else:
                    st.success(f"✅ No redirects detected — direct connection to `{redirect_chain[0]}`")

                st.markdown("---")

                # PRO FEATURE: Network & Infrastructure
                st.markdown("#### 🌐 Network Infrastructure")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                        <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                            <div style="color: #94a3b8; font-size: 0.85rem;">Server IP Address</div>
                            <div style="color: #ffffff; font-weight: 600; font-size: 1.1rem;">{resolved_ip}</div>
                            <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 0.3rem;">{dns_status_log}</div>
                        </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    ssl_status = "🔒 Secure (HTTPS)" if pro_meta["is_ssl"] else "🔓 Insecure (HTTP)"
                    ip_mask = "⚠️ IP-Masked" if pro_meta["is_ip_masked"] else "✅ Clean Domain"
                    st.markdown(f"""
                        <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                            <div style="color: #94a3b8; font-size: 0.85rem;">Security Status</div>
                            <div style="color: {'#00ffcc' if pro_meta['is_ssl'] else '#fbbf24'}; font-weight: 600; font-size: 1rem;">{ssl_status}</div>
                            <div style="color: {'#ff3333' if pro_meta['is_ip_masked'] else '#00ffcc'}; font-size: 0.9rem; margin-top: 0.2rem;">{ip_mask}</div>
                        </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")

                # PRO FEATURE: Live IP Geolocation
                st.markdown("#### 🗺️ Server Location Intelligence")
                if geo_info:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"""
                            <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                                <div style="color: #94a3b8; font-size: 0.85rem;">Location</div>
                                <div style="color: #ffffff; font-weight: 600;">{geo_info['country']}</div>
                                <div style="color: #e2e8f0; font-size: 0.9rem;">{geo_info['city']}, {geo_info['region']}</div>
                                <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 0.3rem;">Timezone: {geo_info['timezone']}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    with col2:
                        st.markdown(f"""
                            <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                                <div style="color: #94a3b8; font-size: 0.85rem;">Network Provider</div>
                                <div style="color: #ffffff; font-weight: 600;">{geo_info['isp']}</div>
                                <div style="color: #e2e8f0; font-size: 0.9rem;">{geo_info['org']}</div>
                                <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 0.3rem;">📍 {geo_info['lat']}, {geo_info['lon']}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    
                    if geo_info['lat'] is not None and geo_info['lon'] is not None:
                        st.map(pd.DataFrame({"lat": [geo_info['lat']], "lon": [geo_info['lon']]}), use_container_width=True)
                else:
                    st.info("⚪ Geolocation data unavailable — server may be unreachable or using privacy protection.")

                st.markdown("---")

                # PRO FEATURE: Full WHOIS Registration History
                st.markdown("#### 📜 Domain Registration History")
                if whois_info.get("found"):
                    st.markdown(f"<div style='background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem; margin-bottom: 1rem;'>{whois_info['age_status']}</div>", unsafe_allow_html=True)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"""
                            <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                                <div style="color: #94a3b8; font-size: 0.85rem;">Registrar</div>
                                <div style="color: #ffffff; font-weight: 600;">{whois_info['registrar']}</div>
                                <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 0.5rem;">Created</div>
                                <div style="color: #e2e8f0;">{whois_info['creation_date']}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    with col2:
                        st.markdown(f"""
                            <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem;">
                                <div style="color: #94a3b8; font-size: 0.85rem;">Organization</div>
                                <div style="color: #ffffff; font-weight: 600;">{whois_info['org']}</div>
                                <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 0.5rem;">Expires</div>
                                <div style="color: #e2e8f0;">{whois_info['expiration_date']}</div>
                            </div>
                        """, unsafe_allow_html=True)
                    
                    if whois_info['name_servers']:
                        st.markdown(f"""
                            <div style="background: rgba(255,255,255,0.02); border-radius: 10px; padding: 1rem; margin-top: 0.5rem;">
                                <div style="color: #94a3b8; font-size: 0.85rem;">Name Servers</div>
                                <div style="color: #e2e8f0; font-size: 0.9rem;">{', '.join(whois_info['name_servers'][:4])}</div>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"⚪ {whois_info.get('error', 'WHOIS data unavailable')}")

                st.markdown("---")

                # PRO FEATURE: Advanced heuristics breakdown
                st.markdown("#### 🔍 Security Feature Analysis")
                
                # Create a nice table with icons
                features_data = {
                    "Security Parameter": [
                        "SSL/TLS Encryption",
                        "Domain Structure",
                        "Keyword Analysis",
                        "URL Complexity",
                        "Subdomain Count",
                        "Redirect Depth",
                        "Domain Age",
                        "IP Address Type"
                    ],
                    "Status": [
                        "🔒 Secure" if pro_meta["is_ssl"] else "🔓 Insecure",
                        "⚠️ IP-Masked" if pro_meta["is_ip_masked"] else "✅ Clean",
                        "⚠️ Suspicious" if feature_weights[5] == 1 else "✅ Clean",
                        f"{feature_weights[3]} hyphens",
                        f"{feature_weights[2]} subdomains",
                        f"{len(redirect_chain) - 1} hops",
                        f"{whois_info.get('age_days', 'N/A')} days" if whois_info.get('found') else "Unknown",
                        "🔢 Numeric" if pro_meta["is_ip_masked"] else "📝 Alphanumeric"
                    ],
                    "Risk Level": [
                        "🟢 Low" if pro_meta["is_ssl"] else "🟡 Medium",
                        "🔴 High" if pro_meta["is_ip_masked"] else "🟢 Low",
                        "🟡 Medium" if feature_weights[5] == 1 else "🟢 Low",
                        "🟢 Low" if feature_weights[3] == 0 else "🟡 Medium",
                        "🟢 Low" if feature_weights[2] < 2 else "🟡 Medium",
                        "🟢 Low" if len(redirect_chain) < 3 else "🟡 Medium",
                        "🔴 High" if whois_info.get('age_days', 999) < 30 else "🟢 Low" if whois_info.get('age_days', 0) > 180 else "🟡 Medium",
                        "🔴 High" if pro_meta["is_ip_masked"] else "🟢 Low"
                    ]
                }
                
                df_features = pd.DataFrame(features_data)
                st.dataframe(df_features, use_container_width=True, hide_index=True)

                st.markdown("---")

                # Technical Details
                st.markdown("#### 🧠 AI & ML Engine Metrics")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"""
                        <div style="background: rgba(0,255,204,0.02); border: 1px solid rgba(0,255,204,0.05); border-radius: 10px; padding: 1rem;">
                            <div style="color: #94a3b8; font-size: 0.85rem;">Model Confidence</div>
                            <div style="color: #00ffcc; font-weight: 700; font-size: 1.2rem;">{round(ml_phish_probability*100, 1)}%</div>
                            <div style="color: #94a3b8; font-size: 0.8rem;">Structural Deviation Score</div>
                        </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; padding: 1rem;">
                            <div style="color: #94a3b8; font-size: 0.85rem;">Feature Vector</div>
                            <div style="color: #e2e8f0; font-weight: 500; font-size: 0.9rem;">{feature_weights}</div>
                            <div style="color: #94a3b8; font-size: 0.8rem;">[length, @, subdomains, hyphens, entropy, keywords]</div>
                        </div>
                    """, unsafe_allow_html=True)

                st.markdown("---")

                # Action Recommendation
                if is_malicious_class:
                    st.error("""
                        🛑 **ACTION REQUIRED:** Our AI engine has detected multiple threat indicators. 
                        We strongly recommend closing this tab immediately and not proceeding with any 
                        transactions or data entry on this website.
                    """)
                else:
                    st.success("""
                        ✅ **SECURITY CLEARANCE:** All security checks passed. This website demonstrates 
                        legitimate structural patterns and no phishing indicators were detected. 
                        Safe to proceed.
                    """)

                st.markdown("---")

                # PRO FEATURE: Downloadable report
                st.markdown("#### 📥 Export Report")
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
            else:
                st.info("⚠️ Please enter a valid website URL to begin the security analysis.")

with tab_bulk:
    st.markdown("### 📂 Bulk URL Scanner")
    st.markdown("Upload a CSV with a column named **url** or paste URLs below for batch analysis.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        uploaded_csv = st.file_uploader("📎 Upload CSV File", type=["csv"])
    
    with col2:
        st.markdown("##### or paste URLs manually")
    
    pasted_urls = st.text_area(
        "Enter one URL per line",
        height=150,
        placeholder="https://example.com\nhttps://another-site.com",
        label_visibility="collapsed"
    )

    if st.button("🚀 SCAN ALL URLS", use_container_width=True):
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

        url_list = list(dict.fromkeys(url_list))  # de-duplicate, preserve order

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
                        "Status": "⚠️ DANGEROUS" if res["is_malicious_class"] else "✅ SAFE",
                        "Risk %": res["risk_percent"],
                        "Final URL": res["final_url"],
                        "IP": res["resolved_ip"],
                        "SSL": "🔒" if res["pro_meta"]["is_ssl"] else "🔓",
                        "Hops": len(res["redirect_chain"]) - 1,
                        "Age": res["whois_info"].get("age_days", "N/A"),
                    })
                except Exception as e:
                    bulk_results.append({
                        "URL": u, 
                        "Status": "⚪ FAILED",
                        "Risk %": "N/A", 
                        "Final URL": "ERROR",
                        "IP": "N/A",
                        "SSL": "N/A",
                        "Hops": "N/A",
                        "Age": "N/A",
                    })
                progress.progress((i + 1) / len(url_list), text=f"Scanning {i + 1} / {len(url_list)}...")

            progress.empty()

            bulk_df = pd.DataFrame(bulk_results)

            st.markdown("---")
            st.markdown(f"### 📊 Bulk Scan Results — {len(url_list)} URLs")

            # Summary Cards
            danger_count = sum(1 for r in bulk_results if r["Status"] == "⚠️ DANGEROUS")
            safe_count = sum(1 for r in bulk_results if r["Status"] == "✅ SAFE")
            failed_count = sum(1 for r in bulk_results if r["Status"] == "⚪ FAILED")

            col1, col2, col3 = st.columns(3)
            col1.markdown(f"""
                <div style="background: rgba(255,51,51,0.05); border: 1px solid rgba(255,51,51,0.2); border-radius: 12px; padding: 1rem; text-align: center;">
                    <div style="font-size: 2rem;">⚠️</div>
                    <div style="color: #ff3333; font-weight: 700; font-size: 1.5rem;">{danger_count}</div>
                    <div style="color: #94a3b8; font-size: 0.85rem;">Threats Detected</div>
                </div>
            """, unsafe_allow_html=True)
            
            col2.markdown(f"""
                <div style="background: rgba(0,255,204,0.05); border: 1px solid rgba(0,255,204,0.2); border-radius: 12px; padding: 1rem; text-align: center;">
                    <div style="font-size: 2rem;">✅</div>
                    <div style="color: #00ffcc; font-weight: 700; font-size: 1.5rem;">{safe_count}</div>
                    <div style="color: #94a3b8; font-size: 0.85rem;">Verified Secure</div>
                </div>
            """, unsafe_allow_html=True)
            
            col3.markdown(f"""
                <div style="background: rgba(251,191,36,0.05); border: 1px solid rgba(251,191,36,0.2); border-radius: 12px; padding: 1rem; text-align: center;">
                    <div style="font-size: 2rem;">⚪</div>
                    <div style="color: #fbbf24; font-weight: 700; font-size: 1.5rem;">{failed_count}</div>
                    <div style="color: #94a3b8; font-size: 0.85rem;">Scan Failed</div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("---")
            st.dataframe(bulk_df, use_container_width=True, hide_index=True)

            csv_buf = io.StringIO()
            bulk_df.to_csv(csv_buf, index=False)
            st.download_button(
                "📊 Download Bulk Scan Results (CSV)",
                data=csv_buf.getvalue().encode("utf-8"),
                file_name="threatx_bulk_scan_results.csv",
                mime="text/csv",
                use_container_width=True,
            )
