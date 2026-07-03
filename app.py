import streamlit as st
import math
import socket
import ssl
import base64
import time
import requests
import datetime
import matplotlib.pyplot as plt
from urllib.parse import urlparse

# ============================================================
#  THREAT-X GLOBAL GUARD — LIVE EDITION (Final, Consolidated)
#  Every signal below is either a real live lookup, or a clearly
#  labeled local heuristic. No fake/simulated calls, no fake ML.
# ============================================================

st.set_page_config(page_title="Threat-X Global Guard", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    .main { background-color: #060814; }
    div.block-container { padding-top: 2rem; }
    h1 { color: #ffffff; text-align: center; font-family: 'Helvetica Neue', Arial, sans-serif; font-weight: 700; }
    h3, h4 { color: #f1f5f9; font-family: 'Helvetica Neue', Arial, sans-serif; }
    .stButton>button { background-color: #00ffcc; color: #060814; font-weight: bold; width: 100%; border-radius: 6px; height: 52px; font-size: 18px; border: none; transition: 0.3s; box-shadow: 0px 4px 15px rgba(0, 255, 204, 0.2); }
    .stButton>button:hover { background-color: #00ccaa; box-shadow: 0px 0px 25px #00ffcc; transform: translateY(-1px); }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    </style>
    """, unsafe_allow_html=True)

st.write("<div style='text-align: center; padding-top: 10px;'><span style='font-size: 38px; font-weight: 800; color: #ffffff; letter-spacing: 1px;'>THREAT</span><span style='font-size: 38px; font-weight: 800; color: #00ffcc; letter-spacing: 1px;'>-X</span><span style='font-size: 14px; font-weight: bold; color: #475569; margin-left: 8px;'>GLOBAL GUARD — LIVE</span></div>", unsafe_allow_html=True)
st.write("<p style='text-align: center; color: #94a3b8; font-size: 15px; font-family: Arial;'>Real-time scan across live threat feeds, DNS, geolocation, SSL, and domain-age records.</p>", unsafe_allow_html=True)
st.write("---")

# ------------------------------------------------------------
# SIDEBAR — optional API keys (free tier available for both)
# ------------------------------------------------------------
with st.sidebar:
    st.header("🔑 Optional Live API Keys")
    st.caption("Leave blank to skip that check. Free keys available at the links below.")
    gsb_key = st.text_input("Google Safe Browsing API Key", type="password",
                             help="https://developers.google.com/safe-browsing/v4/get-started")
    vt_key = st.text_input("VirusTotal API Key", type="password",
                            help="https://www.virustotal.com/gui/join-us")
    st.write("---")
    st.caption("Always live, no key required:")
    st.caption("• URLhaus threat feed\n• Live DNS resolution + IP geolocation\n• SSL certificate inspection\n• WHOIS domain-age lookup")

# ------------------------------------------------------------
# 1. LIVE DNS RESOLUTION + IP GEOLOCATION
# ------------------------------------------------------------
def resolve_dns_and_geolocation(hostname):
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return "0.0.0.0", "🔴 Unresolvable / Offline", "❌ Unreachable Infrastructure"

    geo_string = "🌐 Location lookup unavailable"
    try:
        geo_resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3.0)
        if geo_resp.status_code == 200:
            geo = geo_resp.json()
            if geo.get("status") == "success":
                geo_string = f"🌐 {geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')} ({geo.get('isp', 'Unknown ISP')})"
    except Exception:
        pass

    return ip, "🟢 Live & Resolvable", geo_string

# ------------------------------------------------------------
# 2. LIVE SSL CERTIFICATE INSPECTION
# ------------------------------------------------------------
def check_ssl_certificate(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        issuer = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown Issuer')
        valid = days_left > 0
        return {
            "has_valid_ssl": valid,
            "days_until_expiry": days_left,
            "issuer": issuer,
            "status": f"🟢 Valid — issued by {issuer}, {days_left} days left" if valid else "🔴 Expired Certificate"
        }
    except Exception as e:
        return {
            "has_valid_ssl": False,
            "days_until_expiry": None,
            "issuer": None,
            "status": f"🔴 No valid HTTPS / connection failed ({type(e).__name__})"
        }

# ------------------------------------------------------------
# 3. LIVE WHOIS DOMAIN-AGE LOOKUP (no key required)
# ------------------------------------------------------------
def check_domain_age(hostname):
    try:
        import whois  # python-whois package
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return {"age_days": None, "status": "⚪ WHOIS data unavailable"}
        if isinstance(created, str):
            created = datetime.datetime.fromisoformat(created)
        age_days = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
        if age_days < 30:
            status = f"🔴 Very new domain ({age_days} days old — common phishing trait)"
        elif age_days < 180:
            status = f"🟠 Recently registered ({age_days} days old)"
        else:
            status = f"🟢 Established domain ({age_days} days old)"
        return {"age_days": age_days, "status": status}
    except ImportError:
        return {"age_days": None, "status": "⚪ python-whois not installed (pip install python-whois)"}
    except Exception:
        return {"age_days": None, "status": "⚪ WHOIS lookup failed / privacy-protected record"}

# ------------------------------------------------------------
# 4. LIVE URLHAUS THREAT-FEED LOOKUP (abuse.ch, free, no key)
# ------------------------------------------------------------
def check_urlhaus(target_url):
    try:
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": target_url}, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                return {
                    "listed": True,
                    "reference": data.get("urlhaus_reference", ""),
                    "status": f"🔴 Listed on URLhaus — Threat: {data.get('threat', 'unknown')}"
                }
            return {"listed": False, "reference": "", "status": "🟢 Not present in URLhaus database"}
        return {"listed": False, "reference": "", "status": f"⚪ URLhaus unreachable (HTTP {resp.status_code})"}
    except Exception:
        return {"listed": False, "reference": "", "status": "⚪ URLhaus request failed (timeout/network)"}

# ------------------------------------------------------------
# 5. GOOGLE SAFE BROWSING (live, requires free key)
# ------------------------------------------------------------
def check_google_safe_browsing(target_url, api_key):
    if not api_key:
        return {"matched": False, "status": "⚪ Skipped — no API key provided"}
    try:
        body = {
            "client": {"clientId": "threat-x-global-guard", "clientVersion": "13.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}]
            }
        }
        resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                              json=body, timeout=6)
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            if matches:
                types = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
                return {"matched": True, "status": f"🔴 Match found — {types}"}
            return {"matched": False, "status": "🟢 Clean — no match"}
        return {"matched": False, "status": f"⚪ API error (HTTP {resp.status_code})"}
    except Exception:
        return {"matched": False, "status": "⚪ Request failed"}

# ------------------------------------------------------------
# 6. VIRUSTOTAL (live, requires free key)
# ------------------------------------------------------------
def check_virustotal(target_url, api_key):
    if not api_key:
        return {"malicious_votes": 0, "total_votes": 0, "status": "⚪ Skipped — no API key provided"}
    try:
        headers = {"x-apikey": api_key}
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)

        if resp.status_code == 404:
            sub = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers,
                                 data={"url": target_url}, timeout=8)
            if sub.status_code in (200, 201):
                return {"malicious_votes": 0, "total_votes": 0,
                        "status": "🟡 Submitted for first-time analysis — re-scan shortly for results"}
            return {"malicious_votes": 0, "total_votes": 0, "status": f"⚪ Submission failed (HTTP {sub.status_code})"}

        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            status = f"🔴 {flagged}/{total} engines flag this URL" if flagged > 0 else f"🟢 0/{total} engines flag this URL"
            return {"malicious_votes": flagged, "total_votes": total, "status": status}

        return {"malicious_votes": 0, "total_votes": 0, "status": f"⚪ API error (HTTP {resp.status_code})"}
    except Exception:
        return {"malicious_votes": 0, "total_votes": 0, "status": "⚪ Request failed"}

# ------------------------------------------------------------
# 7. LOCAL LEXICAL / STRUCTURAL HEURISTICS (deterministic, transparent)
# ------------------------------------------------------------
def extract_lexical_signals(url):
    clean = url.lower().strip()
    is_https = clean.startswith('https')
    clean_no_scheme = clean.replace('https://', '').replace('http://', '')

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc if parsed.netloc else clean_no_scheme.split('/')[0]

    length = len(clean_no_scheme)
    has_at = "@" in clean_no_scheme
    subdomains = max(0, len(host.split('.')) - 2)
    has_dash = "-" in host
    is_ip_host = host.replace('.', '').isdigit()

    probs = [float(host.count(c)) / len(host) for c in set(host)] if len(host) > 0 else [0.0]
    entropy = -sum(p * math.log(p, 2) for p in probs) if len(host) > 0 else 0.0

    digits = sum(c.isdigit() for c in host)
    digit_ratio = round(digits / len(host), 2) if len(host) > 0 else 0.0

    suspicious_keywords = ['login', 'verify', 'secure', 'billing', 'update', 'account',
                            'confirm', 'password', 'auth', 'wallet', 'suspend']
    trusted_roots = ['google.com', 'github.com', 'wikipedia.org', 'paypal.com',
                      'microsoft.com', 'apple.com', 'amazon.com']
    has_keyword = any(kw in clean_no_scheme for kw in suspicious_keywords) and not any(t in host for t in trusted_roots)

    return {
        "host": host, "length": length, "has_at": has_at, "subdomains": subdomains,
        "has_dash": has_dash, "is_ip_host": is_ip_host, "entropy": round(entropy, 2),
        "digit_ratio": digit_ratio, "is_https": is_https, "has_keyword": has_keyword
    }

# ------------------------------------------------------------
# RISK AGGREGATION — weighted combination of all real signals
# ------------------------------------------------------------
def compute_risk_score(lex, dns_ip, ssl_info, whois_info, urlhaus, gsb, vt):
    score = 0.0

    if urlhaus["listed"]:
        score += 45
    if gsb["matched"]:
        score += 45
    if vt["total_votes"] > 0:
        score += min(35, (vt["malicious_votes"] / max(vt["total_votes"], 1)) * 60)

    if dns_ip == "0.0.0.0":
        score += 15
    if not ssl_info["has_valid_ssl"]:
        score += 10
    if not lex["is_https"]:
        score += 5
    if whois_info["age_days"] is not None and whois_info["age_days"] < 30:
        score += 15
    elif whois_info["age_days"] is not None and whois_info["age_days"] < 180:
        score += 7

    if lex["has_at"]:
        score += 8
    if lex["is_ip_host"]:
        score += 10
    if lex["subdomains"] >= 3:
        score += 6
    if lex["has_dash"]:
        score += 3
    if lex["entropy"] > 4.0:
        score += 5
    if lex["digit_ratio"] > 0.15:
        score += 4
    if lex["has_keyword"]:
        score += 8

    return round(min(99.0, max(1.0, score)), 1)

# ------------------------------------------------------------
# UI — INPUT
# ------------------------------------------------------------
user_target = st.text_input("🔗 Enter website link to analyze:", placeholder="e.g., https://example.com")

if st.button("🔍 SCAN WEBSITE NOW"):
    if user_target:
        start_time = time.time()
        with st.spinner("Querying live threat feeds, DNS, SSL and WHOIS records..."):
            lex = extract_lexical_signals(user_target)
            host = lex["host"]

            resolved_ip, dns_status_log, geo_location_log = resolve_dns_and_geolocation(host)
            ssl_info = check_ssl_certificate(host)
            whois_info = check_domain_age(host)
            urlhaus = check_urlhaus(user_target)
            gsb = check_google_safe_browsing(user_target, gsb_key)
            vt = check_virustotal(user_target, vt_key)

            risk_percent = compute_risk_score(lex, resolved_ip, ssl_info, whois_info, urlhaus, gsb, vt)
            safety_percent = round(100.0 - risk_percent, 1)
            is_malicious_class = risk_percent >= 45.0
        execution_latency = round(time.time() - start_time, 2)

        # ------------------------------------------------------------
        # DASHBOARD
        # ------------------------------------------------------------
        st.write("---")
        st.write("### 📊 Live Threat Analysis Report")

        m_col1, m_col2, m_col3 = st.columns(3)
        if is_malicious_class:
            m_col1.metric("🛡️ SCANNER STATUS", "⚠️ DANGEROUS", "RISK DETECTED", delta_color="inverse")
            m_col2.metric("🚨 RISK SCORE", f"{risk_percent}%", "HIGH RISK", delta_color="inverse")
            m_col3.metric("🟢 SAFETY FACTOR", f"{safety_percent}%", "UNSAFE ZONE", delta_color="inverse")
        else:
            m_col1.metric("🛡️ SCANNER STATUS", "✅ LOOKS SAFE", "NO STRONG SIGNALS")
            m_col2.metric("🚨 RISK SCORE", f"{risk_percent}%", "LOW RISK")
            m_col3.metric("🟢 SAFETY FACTOR", f"{safety_percent}%", "SECURE OPERATIONS")

        st.write("---")

        fig_pie, ax = plt.subplots(figsize=(6, 2.4))
        fig_pie.patch.set_facecolor('#060814')
        ax.set_facecolor('#060814')
        colors = ['#00ffcc', '#ff3333'] if not is_malicious_class else ['#161c2e', '#ff3333']
        ax.pie([safety_percent, risk_percent], labels=['Safety Index', 'Risk Index'], colors=colors,
               autopct='%1.1f%%', startangle=90, textprops=dict(color="w", weight="bold", size=10),
               wedgeprops=dict(width=0.4, edgecolor='#1e293b'))
        ax.axis('equal')
        st.pyplot(fig_pie)
        plt.close()

        st.write("---")
        st.write("#### 📡 Live Threat Feed Results")
        c1, c2 = st.columns(2)
        with c1:
            st.write(f"**URLhaus:** {urlhaus['status']}")
            if urlhaus["listed"] and urlhaus["reference"]:
                st.write(f"↳ [View report]({urlhaus['reference']})")
            st.write(f"**Google Safe Browsing:** {gsb['status']}")
        with c2:
            st.write(f"**VirusTotal:** {vt['status']}")
            st.write(f"**WHOIS Domain Age:** {whois_info['status']}")

        st.write("---")
        st.write("#### 🌐 Infrastructure & Location")
        i1, i2 = st.columns(2)
        with i1:
            st.write(f"**Resolved IP:** `{resolved_ip}`")
            st.write(f"**DNS Status:** {dns_status_log}")
            st.write(f"**Geolocation:** {geo_location_log}")
        with i2:
            st.write(f"**SSL Certificate:** {ssl_info['status']}")

        st.write("---")
        st.write("#### 🧠 Lexical / Structural Signals (local heuristics)")
        st.info(
            f"Host: `{lex['host']}` | Length: `{lex['length']}` | Subdomains: `{lex['subdomains']}` | "
            f"Entropy: `{lex['entropy']}` | Digit ratio: `{lex['digit_ratio']}` | HTTPS: `{lex['is_https']}` | "
            f"Has '@': `{lex['has_at']}` | IP-based host: `{lex['is_ip_host']}` | Suspicious keyword: `{lex['has_keyword']}`"
        )
        st.caption(f"⏱️ Total scan latency: {execution_latency}s")

        st.write("---")
        if is_malicious_class:
            st.error("🛑 This URL shows real, live indicators of risk. Avoid entering credentials or personal data.")
        else:
            st.success("✔ No strong live threat signals were found. Always stay cautious with unfamiliar links regardless.")
    else:
        st.info("Please provide a valid website address to run a live scan.")
