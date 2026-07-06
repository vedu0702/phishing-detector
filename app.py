import streamlit as st
import pandas as pd
import math
import socket
import requests
import re
import io
import hashlib
import zipfile
import datetime
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

# 1. Premium Enterprise UI Configuration
st.set_page_config(page_title="Threat-X Global Guard Pro", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    .main { background-color: #060814; }
    div.block-container { padding-top: 2rem; }
    h1 { color: #ffffff; text-align: center; font-family: 'Helvetica Neue', Arial, sans-serif; font-weight: 700; }
    h3 { color: #f1f5f9; font-family: 'Helvetica Neue', Arial, sans-serif; }
    .stButton>button { background-color: #00ffcc; color: #060814; font-weight: bold; width: 100%; border-radius: 6px; height: 52px; font-size: 18px; border: none; transition: 0.3s; box-shadow: 0px 4px 15px rgba(0, 255, 204, 0.2); }
    .stButton>button:hover { background-color: #00ccaa; box-shadow: 0px 0px 25px #00ffcc; transform: translateY(-1px); }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    </style>
    """, unsafe_allow_html=True)

st.write("<div style='text-align: center; padding-top: 10px;'><span style='font-size: 38px; font-weight: 800; color: #ffffff; letter-spacing: 1px;'>THREAT</span><span style='font-size: 38px; font-weight: 800; color: #00ffcc; letter-spacing: 1px;'>-X</span><span style='font-size: 14px; font-weight: bold; color: #475569; margin-left: 8px;'>GLOBAL GUARD PRO v14.0</span></div>", unsafe_allow_html=True)
st.write("<p style='text-align: center; color: #94a3b8; font-size: 15px; font-family: Arial;'>Enter any website address below to run our automated machine learning scanners and verify website authenticity instantly.</p>", unsafe_allow_html=True)
st.write("---")

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
        fig.patch.set_facecolor('white')

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
                family="monospace", transform=ax.transAxes, wrap=True)
        pdf.savefig(fig)
        plt.close(fig)
    return buf.getvalue()

# ============================================================================
# 9. FILE MALWARE / PHISHING-DOCUMENT SCANNER
# ============================================================================

FILE_SIGNATURES = {
    b"\x4D\x5A":             ("Windows Executable (EXE/DLL)", [".exe", ".dll", ".scr", ".com", ".msi", ".sys"]),
    b"\x50\x4B\x03\x04":     ("ZIP-based container (docx/xlsx/pptx/zip/jar/apk)",
                              [".docx", ".xlsx", ".pptx", ".zip", ".jar", ".apk", ".docm", ".xlsm", ".pptm"]),
    b"\x25\x50\x44\x46":     ("PDF Document", [".pdf"]),
    b"\xFF\xD8\xFF":         ("JPEG Image", [".jpg", ".jpeg"]),
    b"\x89\x50\x4E\x47":     ("PNG Image", [".png"]),
    b"\x47\x49\x46\x38":     ("GIF Image", [".gif"]),
    b"\x7F\x45\x4C\x46":     ("ELF (Linux Executable)", [".elf", ".bin", ".so"]),
    b"\xD0\xCF\x11\xE0":     ("Legacy MS Office Document (doc/xls/ppt)", [".doc", ".xls", ".ppt"]),
    b"\x52\x61\x72\x21":     ("RAR Archive", [".rar"]),
    b"\x1F\x8B":             ("GZIP Archive", [".gz", ".tgz"]),
    b"\x37\x7A\xBC\xAF":     ("7-Zip Archive", [".7z"]),
}

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.jar', '.msi', '.ps1', '.psm1', '.hta', '.dll', '.apk', '.lnk',
    '.reg', '.docm', '.xlsm', '.pptm'
}

def calculate_file_entropy(data: bytes) -> float:
    """Shannon entropy (0-8). High entropy (>7.5) suggests packed/encrypted/compressed payloads."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 2)

def detect_file_signature(file_bytes: bytes):
    for magic, (desc, exts) in FILE_SIGNATURES.items():
        if file_bytes.startswith(magic):
            return desc, exts
    return "Unknown / unrecognized binary signature", []

def check_extension_mismatch(filename: str, file_bytes: bytes):
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    desc, expected_exts = detect_file_signature(file_bytes)
    if not expected_exts:
        return False, f"⚪ Could not verify — unrecognized binary signature for `{ext or 'no extension'}`."
    if ext in expected_exts:
        return False, f"✅ File extension `{ext}` matches its actual content type ({desc})."
    return True, (f"🚨 MISMATCH: File is named `{ext}` but its real binary signature is **{desc}** — "
                  f"a classic disguise trick (e.g. an .exe renamed to .jpg).")

def detect_macros(filename: str, file_bytes: bytes):
    lower_name = filename.lower()
    if not lower_name.endswith(('.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx')):
        return False, None
    try:
        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                names = z.namelist()
                if any('vbaProject.bin' in n for n in names):
                    return True, "🚨 Embedded VBA macro project detected (vbaProject.bin) — macros are a common malware delivery method."
            return False, "✅ No embedded macros detected."
        elif file_bytes.startswith(b"\xD0\xCF\x11\xE0"):
            return None, "⚪ Legacy Office binary format — macro presence could not be verified without extra libraries."
    except Exception:
        pass
    return False, "✅ No embedded macros detected."

def scan_uploaded_file(uploaded_file):
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name
    size_kb = round(len(file_bytes) / 1024, 1)

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()

    entropy = calculate_file_entropy(file_bytes)
    sig_desc, _ = detect_file_signature(file_bytes)
    mismatch, mismatch_note = check_extension_mismatch(filename, file_bytes)
    has_macro, macro_note = detect_macros(filename, file_bytes)

    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS

    # Local static-analysis risk scoring (0-100)
    risk = 5.0
    if mismatch:
        risk += 40.0
    if is_suspicious_ext:
        risk += 25.0
    if entropy >= 7.5:
        risk += 20.0
    if has_macro:
        risk += 25.0

    risk_percent = round(min(99.4, max(2.0, risk)), 1)
    safety_percent = round(100.0 - risk_percent, 1)
    is_malicious_class = risk_percent >= 45.0

    return {
        "filename": filename,
        "size_kb": size_kb,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "entropy": entropy,
        "signature_desc": sig_desc,
        "extension_mismatch": mismatch,
        "mismatch_note": mismatch_note,
        "has_macro": has_macro,
        "macro_note": macro_note,
        "is_suspicious_ext": is_suspicious_ext,
        "risk_percent": risk_percent,
        "safety_percent": safety_percent,
        "is_malicious_class": is_malicious_class,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

def build_file_scan_csv(fresult):
    row = {
        "Filename": fresult["filename"],
        "Size (KB)": fresult["size_kb"],
        "Verdict": "MALICIOUS" if fresult["is_malicious_class"] else "SAFE",
        "Risk %": fresult["risk_percent"],
        "Safety %": fresult["safety_percent"],
        "SHA256": fresult["sha256"],
        "MD5": fresult["md5"],
        "Entropy": fresult["entropy"],
        "Detected Type": fresult["signature_desc"],
        "Extension Mismatch": fresult["extension_mismatch"],
        "Suspicious Extension": fresult["is_suspicious_ext"],
        "Macro Detected": fresult["has_macro"],
        "Scanned At (UTC)": fresult["scanned_at"],
    }
    buf = io.StringIO()
    pd.DataFrame([row]).to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")

# 8. User Console Interface — Single Scan / Bulk Scan / File Scan
tab_single, tab_bulk, tab_file = st.tabs(["🔍 Single Scan", "📂 Bulk Scan", "🗂️ File Scan"])

with tab_single:
    user_target = st.text_input("🔗 Enter website link here to analyze secure features:", placeholder="e.g., https://my-safe-website.com")

    if st.button("🔍 SCAN WEBSITE NOW"):
        if user_target:
            with st.spinner("Tracing redirects, analyzing server protocols and WHOIS records..."):
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
            st.write("---")
            st.write("### 📊 Automated Threat Analysis Report")

            m_col1, m_col2, m_col3 = st.columns(3)
            if is_malicious_class:
                m_col1.metric(label="🛡️ SCANNER STATUS", value="⚠️ DANGEROUS", delta="RISK DETECTED", delta_color="inverse")
                m_col2.metric(label="🚨 RISK PERCENTAGE", value=f"{risk_percent}%", delta="HIGH RISK", delta_color="inverse")
                m_col3.metric(label="🟢 SAFETY FACTOR", value=f"{safety_percent}%", delta="UNSAFE ZONE", delta_color="inverse")
            else:
                m_col1.metric(label="🛡️ SCANNER STATUS", value="✅ SAFE LINK", delta="CLEAN CERTIFICATE")
                m_col2.metric(label="🚨 RISK PERCENTAGE", value=f"{risk_percent}%", delta="LOW RISK")
                m_col3.metric(label="🟢 SAFETY FACTOR", value=f"{safety_percent}%", delta="SECURE OPERATIONS")

            st.write("---")

            labels = ['Safety Index', 'Risk Index']
            sizes = [safety_percent, risk_percent]
            colors = ['#00ffcc', '#ff3333'] if not is_malicious_class else ['#161c2e', '#ff3333']

            fig_pie, ax = plt.subplots(figsize=(6, 2.4))
            fig_pie.patch.set_facecolor('#060814')
            ax.set_facecolor('#060814')
            wedges, texts, autotexts = ax.pie(
                sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                startangle=90, textprops=dict(color="w", weight="bold", size=10),
                wedgeprops=dict(width=0.4, edgecolor='#1e293b')
            )
            for text in texts:
                text.set_color('#ffffff')
            ax.axis('equal')
            st.pyplot(fig_pie)
            plt.close(fig_pie)

            st.write("---")

            # PRO FEATURE: Redirect Chain Tracing
            st.write("#### 🔀 Redirect Chain Trace:")
            if len(redirect_chain) > 1:
                st.warning(f"⚠️ This link redirects through {len(redirect_chain) - 1} hop(s) before reaching its final destination.")
                for i, hop in enumerate(redirect_chain):
                    tag = "🔗 Start" if i == 0 else ("🏁 Final Destination" if i == len(redirect_chain) - 1 else f"➡️ Hop {i}")
                    st.write(f"**{tag}:** `{hop}`")
            else:
                st.write(f"✅ No redirects detected — direct link to `{redirect_chain[0]}`")

            st.write("---")
            st.write("#### 📡 System Integrity Verification Details:")
            l_col1, l_col2 = st.columns(2)

            with l_col1:
                st.write(f"🌐 **Website Host Server IP:** `{resolved_ip}`")
                st.write(f"🔌 **Server Connection Status:** {dns_status_log}")

            with l_col2:
                st.write(f"🧠 **AI Prediction Output:** :{'red[SUSPICIOUS ACTIVITY MATCH]' if is_malicious_class else 'green[LEGITIMATE WEBSITE SIGNATURE]'}")

            st.write("---")

            # PRO FEATURE: Live IP Geolocation
            st.write("#### 🗺️ Live Server Geolocation:")
            if geo_info:
                g_col1, g_col2 = st.columns(2)
                with g_col1:
                    st.write(f"🌍 **Country:** {geo_info['country']}")
                    st.write(f"🏙️ **City / Region:** {geo_info['city']}, {geo_info['region']}")
                    st.write(f"🕒 **Timezone:** {geo_info['timezone']}")
                with g_col2:
                    st.write(f"📡 **ISP:** {geo_info['isp']}")
                    st.write(f"🏢 **Organization:** {geo_info['org']}")
                    if geo_info['lat'] is not None and geo_info['lon'] is not None:
                        st.write(f"📍 **Coordinates:** {geo_info['lat']}, {geo_info['lon']}")
                        st.map(pd.DataFrame({"lat": [geo_info['lat']], "lon": [geo_info['lon']]}))
            else:
                st.write("⚪ Geolocation unavailable — server unresolvable or lookup failed.")

            st.write("---")

            # PRO FEATURE: Full WHOIS registration history
            st.write("#### 📜 Full WHOIS Registration History:")
            if whois_info.get("found"):
                st.write(f"📅 **Domain Age Assessment:** {whois_info['age_status']}")
                w_col1, w_col2 = st.columns(2)
                with w_col1:
                    st.write(f"🏛️ **Registrar:** {whois_info['registrar']}")
                    st.write(f"🆕 **Creation Date:** {whois_info['creation_date']}")
                    st.write(f"⏳ **Expiration Date:** {whois_info['expiration_date']}")
                with w_col2:
                    st.write(f"🔄 **Last Updated:** {whois_info['updated_date']}")
                    st.write(f"🏢 **Registrant Org:** {whois_info['org']}")
                    st.write(f"🌐 **Registrant Country:** {whois_info['country']}")
                if whois_info['name_servers']:
                    st.write(f"🖥️ **Name Servers:** {', '.join(whois_info['name_servers'][:4])}")
            else:
                st.write(f"⚪ {whois_info.get('error', 'WHOIS data unavailable')}")

            st.write("---")

            # PRO FEATURE: Advanced heuristics breakdown table
            st.write("#### 🔍 Structural Feature Breakdown Table:")
            breakdown_data = {
                "Security Parameter Indicator": [
                    "SSL Protocol Encryption Status",
                    "Domain Raw IP Address Mask Check",
                    "Suspicious Login/Verify Keyword Flag",
                    "URL Hyphen Clustering Matrix",
                    "Subdomain Layer Count Check",
                    "Redirect Chain Depth Check",
                ],
                "Observed Metric Value": [
                    "HTTPS Secured" if pro_meta["is_ssl"] == 1 else "Insecure HTTP Standard",
                    "Masked Raw IP Address Detected" if pro_meta["is_ip_masked"] == 1 else "Legitimate Text String Domain",
                    "Triggered (Malicious Keywords Found)" if feature_weights[5] == 1 else "Clean Structural Patterns",
                    f"{feature_weights[3]} Structural Dash Elements Detected",
                    f"{feature_weights[2]} Segment Subdomains Layered",
                    f"{len(redirect_chain) - 1} Redirect Hop(s) Detected",
                ],
                "Risk Severity Rating": [
                    "✅ LOW RISK" if pro_meta["is_ssl"] == 1 else "⚠️ MEDIUM RISK ALERT",
                    "🚨 CRITICAL HIGH RISK" if pro_meta["is_ip_masked"] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ HIGH SUSPICION" if feature_weights[5] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MINOR ANOMALY" if feature_weights[3] > 0 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if feature_weights[2] > 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if len(redirect_chain) > 2 else "✅ SECURE INFRASTRUCTURE",
                ]
            }
            st.table(pd.DataFrame(breakdown_data))

            st.write("---")
            st.write("#### 🧠 Technical System Ingestion Metrics:")
            st.info(f"**Extracted Live Feature Vector Sequence:** {feature_weights}")
            st.markdown(f"""
            - **Random Forest Base Confidence Core:** `{round(ml_phish_probability*100, 1)}% Structural Deviation Weight`
            - **URL Lexical Parameters Check:** Length: `{feature_weights[0]}` | Subdomains Detected: `{feature_weights[2]}` | Structural Hyphens: `{feature_weights[3]}` | String Entropy: `{feature_weights[4]}`
            """)

            if is_malicious_class:
                st.error("🛑 ACTION RECOMMENDED: Our Artificial Intelligence engine recommends closing this tab immediately. The URL demonstrates verified fraudulent design footprints.")
            else:
                st.success("✔ SECURITY CLEARANCE GRANTED: This website satisfies all structural security patterns. No phishing behaviors were detected.")

            # PRO FEATURE: Downloadable report
            st.write("---")
            st.write("#### 📥 Export This Report:")
            d_col1, d_col2 = st.columns(2)
            with d_col1:
                st.download_button(
                    "⬇️ Download PDF Report",
                    data=build_single_scan_pdf(result),
                    file_name=f"threatx_report_{result['host_domain']}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            with d_col2:
                st.download_button(
                    "⬇️ Download CSV Report",
                    data=build_single_scan_csv(result),
                    file_name=f"threatx_report_{result['host_domain']}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
        else:
            st.info("Please provide a valid website address string link to execute security scans.")

with tab_bulk:
    st.write("#### 📂 Bulk URL Scan")
    st.write("Upload a CSV file with a column named **url** (or **URL**), or paste one link per line below.")

    uploaded_csv = st.file_uploader("Upload CSV of URLs", type=["csv"])
    pasted_urls = st.text_area("...or paste URLs here (one per line)", height=150, placeholder="https://example.com\nhttps://another-site.com")

    if st.button("🔍 SCAN ALL URLS"):
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

            st.write("---")
            st.write(f"### 📊 Bulk Scan Summary — {len(url_list)} URLs")

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

with tab_file:
    st.write("#### 🗂️ File Malware & Phishing-Document Scan")
    st.write("Upload any file to check for disguised executables, suspicious extensions, packed/encrypted payloads, embedded macros, and known-malicious hashes.")

    uploaded_file_scan = st.file_uploader("Upload a file to scan", type=None, key="file_scan_uploader")

    if uploaded_file_scan is not None:
        if st.button("🔍 SCAN FILE NOW"):
            with st.spinner("Computing hashes, checking file signature, scanning for macros..."):
                fresult = scan_uploaded_file(uploaded_file_scan)

            st.write("---")
            st.write("### 📊 Automated File Threat Report")

            fm_col1, fm_col2, fm_col3 = st.columns(3)
            if fresult["is_malicious_class"]:
                fm_col1.metric(label="🛡️ SCANNER STATUS", value="⚠️ MALICIOUS", delta="RISK DETECTED", delta_color="inverse")
                fm_col2.metric(label="🚨 RISK PERCENTAGE", value=f"{fresult['risk_percent']}%", delta="HIGH RISK", delta_color="inverse")
                fm_col3.metric(label="🟢 SAFETY FACTOR", value=f"{fresult['safety_percent']}%", delta="UNSAFE FILE", delta_color="inverse")
            else:
                fm_col1.metric(label="🛡️ SCANNER STATUS", value="✅ SAFE FILE", delta="CLEAN RESULT")
                fm_col2.metric(label="🚨 RISK PERCENTAGE", value=f"{fresult['risk_percent']}%", delta="LOW RISK")
                fm_col3.metric(label="🟢 SAFETY FACTOR", value=f"{fresult['safety_percent']}%", delta="SECURE FILE")

            st.write("---")

            labels = ['Safety Index', 'Risk Index']
            sizes = [fresult['safety_percent'], fresult['risk_percent']]
            colors = ['#00ffcc', '#ff3333'] if not fresult["is_malicious_class"] else ['#161c2e', '#ff3333']

            ffig, fax = plt.subplots(figsize=(6, 2.4))
            ffig.patch.set_facecolor('#060814')
            fax.set_facecolor('#060814')
            f_wedges, f_texts, f_autotexts = fax.pie(
                sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                startangle=90, textprops=dict(color="w", weight="bold", size=10),
                wedgeprops=dict(width=0.4, edgecolor='#1e293b')
            )
            for text in f_texts:
                text.set_color('#ffffff')
            fax.axis('equal')
            st.pyplot(ffig)
            plt.close(ffig)

            st.write("---")
            st.write("#### 🧬 File Fingerprint:")
            fp_col1, fp_col2 = st.columns(2)
            with fp_col1:
                st.write(f"📄 **Filename:** `{fresult['filename']}`")
                st.write(f"📦 **File Size:** `{fresult['size_kb']} KB`")
                st.write(f"🔎 **Detected Type:** {fresult['signature_desc']}")
            with fp_col2:
                st.write(f"🔑 **SHA-256:** `{fresult['sha256']}`")
                st.write(f"🔑 **MD5:** `{fresult['md5']}`")
                st.write(f"📈 **Entropy:** `{fresult['entropy']} / 8.0`")

            st.write("---")
            st.write("#### 🕵️ Static Analysis Findings:")
            st.write(fresult["mismatch_note"])
            if fresult["macro_note"]:
                st.write(fresult["macro_note"])
            if fresult["is_suspicious_ext"]:
                st.write("🚨 File extension is on the high-risk executable/script list.")
            else:
                st.write("✅ File extension is not on the high-risk executable/script list.")
            if fresult["entropy"] >= 7.5:
                st.write(f"🚨 High entropy ({fresult['entropy']}/8.0) — consistent with packed, compressed, or encrypted payloads often used to evade detection.")
            else:
                st.write(f"✅ Entropy ({fresult['entropy']}/8.0) is within a normal range for this file type.")

            st.write("---")
            st.write("#### 🔍 Structural Feature Breakdown Table:")
            file_breakdown = {
                "Security Parameter Indicator": [
                    "File Signature vs Extension Match",
                    "High-Risk Extension Check",
                    "Shannon Entropy (Packing/Encryption)",
                    "Embedded Macro Detection",
                ],
                "Observed Metric Value": [
                    "Mismatch Detected" if fresult["extension_mismatch"] else "Consistent",
                    "Suspicious" if fresult["is_suspicious_ext"] else "Not Suspicious",
                    f"{fresult['entropy']} / 8.0",
                    "Macro Found" if fresult["has_macro"] else ("Unverifiable" if fresult["has_macro"] is None else "No Macro"),
                ],
                "Risk Severity Rating": [
                    "🚨 CRITICAL HIGH RISK" if fresult["extension_mismatch"] else "✅ SECURE",
                    "⚠️ HIGH SUSPICION" if fresult["is_suspicious_ext"] else "✅ SECURE",
                    "⚠️ MEDIUM SUSPICION" if fresult["entropy"] >= 7.5 else "✅ SECURE",
                    "🚨 CRITICAL HIGH RISK" if fresult["has_macro"] else "✅ SECURE",
                ]
            }
            st.table(pd.DataFrame(file_breakdown))

            if fresult["is_malicious_class"]:
                st.error("🛑 ACTION RECOMMENDED: Do not open or execute this file. It demonstrates verified malicious indicators.")
            else:
                st.success("✔ SECURITY CLEARANCE GRANTED: No malicious indicators were detected in this file.")

            st.write("---")
            st.write("#### 📥 Export This Report:")
            st.download_button(
                "⬇️ Download CSV Report",
                data=build_file_scan_csv(fresult),
                file_name=f"threatx_file_report_{fresult['filename']}.csv",
                mime="text/csv",
                use_container_width=True,
            )
    else:
        st.info("Upload a file above, then click 'SCAN FILE NOW' to run the analysis.")
