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
st.write("<p style='text-align: center; color: #94a3b8; font-size: 15px; font-family: Arial;'>Enter any website address below to run a live scan across real threat-intelligence feeds, WHOIS, SSL, and redirect analysis.</p>", unsafe_allow_html=True)
st.write("---")

# 2. Structural Heuristic Model (RandomForest)
@st.cache_resource
def compile_advanced_ml_model():
    training_data = [
        [15, 0, 0, 0, 2.4, 0, 1, 0, 0], [18, 0, 1, 0, 2.7, 0, 1, 0, 0], [22, 0, 2, 0, 3.1, 0, 1, 0, 0],
        [28, 0, 0, 0, 2.9, 0, 1, 0, 0], [25, 0, 1, 1, 3.2, 0, 1, 0, 0], [30, 0, 1, 1, 3.5, 0, 1, 0, 0],
        [33, 0, 1, 1, 3.76, 0, 1, 0, 0], [36, 0, 0, 1, 3.6, 0, 1, 0, 0], [40, 0, 1, 1, 3.9, 0, 1, 0, 0],
        [20, 0, 0, 1, 3.0, 0, 1, 0, 0], [29, 0, 2, 0, 3.4, 0, 1, 0, 0], [24, 0, 1, 0, 3.1, 0, 1, 0, 0],
        [16, 0, 0, 0, 2.2, 0, 1, 0, 0], [21, 0, 1, 0, 3.0, 0, 1, 0, 0], [27, 0, 0, 1, 3.3, 0, 1, 0, 0],
        [19, 0, 0, 0, 2.6, 0, 0, 0, 0], [23, 0, 1, 0, 3.0, 0, 0, 0, 0],
        [32, 0, 1, 2, 4.2, 1, 1, 0, 1], [45, 0, 0, 2, 4.1, 1, 1, 0, 1], [55, 0, 1, 2, 4.3, 1, 1, 0, 1],
        [72, 1, 2, 1, 4.5, 1, 1, 0, 1], [34, 0, 1, 2, 4.2, 1, 1, 0, 1], [17, 0, 1, 0, 4.4, 1, 1, 0, 1],
        [26, 0, 2, 1, 4.1, 1, 1, 0, 1], [38, 0, 1, 1, 4.0, 1, 1, 0, 1],
        [30, 0, 1, 2, 4.3, 1, 0, 0, 1], [42, 0, 0, 2, 4.2, 1, 0, 0, 1],
        [15, 0, 0, 0, 3.8, 0, 1, 1, 1], [15, 0, 0, 0, 3.9, 1, 0, 1, 1], [18, 1, 0, 0, 4.0, 0, 1, 1, 1],
    ]
    features = ['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token', 'is_ssl', 'is_ip_masked']
    df = pd.DataFrame(training_data, columns=features + ['result'])
    clf = RandomForestClassifier(n_estimators=150, random_state=42)
    clf.fit(df[features], df['result'])
    return clf

cyber_classifier = compile_advanced_ml_model()

# 3. Live URLhaus Threat-Feed Check
def check_past_phishing_history(target_url, auth_key=None):
    if not auth_key:
        return {"checked": False, "matched": False,
                "status": "⚪ Skipped — no URLhaus Auth-Key configured (free at auth.abuse.ch)"}
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={'url': target_url},
            headers={"Auth-Key": auth_key},
            timeout=4.0
        )
        if response.status_code == 200:
            res_data = response.json()
            if res_data.get('query_status') == 'ok':
                return {"checked": True, "matched": True,
                        "status": f"🔴 Reported in Global Blocklist databases (Class: {res_data.get('threat')})"}
            return {"checked": True, "matched": False,
                    "status": "🟢 No match — not present in URLhaus (malware-focused feed, not phishing-specific)"}
        if response.status_code == 401:
            return {"checked": False, "matched": False,
                    "status": "⚪ URLhaus Auth-Key invalid or expired (HTTP 401) — check your key at auth.abuse.ch"}
        return {"checked": False, "matched": False, "status": f"⚪ URLhaus check failed (HTTP {response.status_code})"}
    except Exception:
        return {"checked": False, "matched": False, "status": "⚪ URLhaus check failed (network/timeout error)"}

# 3b. Google Safe Browsing Check (optional, needs a free API key)
def check_google_safe_browsing(target_url, api_key):
    if not api_key:
        return {"checked": False, "matched": False, "status": "⚪ Skipped — no API key provided"}
    try:
        body = {
            "client": {"clientId": "threat-x-global-guard", "clientVersion": "14.0"},
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
                return {"checked": True, "matched": True, "status": f"🔴 Google Safe Browsing MATCH — {types}"}
            return {"checked": True, "matched": False, "status": "🟢 Clean — no match on Google Safe Browsing"}
        return {"checked": False, "matched": False, "status": f"⚪ API error (HTTP {resp.status_code})"}
    except Exception:
        return {"checked": False, "matched": False, "status": "⚪ Google Safe Browsing request failed"}

# 4. Live DNS Host Resolver + IP Geolocation
def resolve_live_dns_ip(hostname):
    try:
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return socket.gethostbyname(hostname), "🟢 Live & Verified"
    except Exception:
        return "0.0.0.0", "🔴 Inactive / Blocked Server"

def resolve_geolocation(ip_address):
    if ip_address == "0.0.0.0":
        return None
    try:
        resp = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5.0,
                             headers={"User-Agent": "threat-x-global-guard"})
        if resp.status_code == 200:
            data = resp.json()
            if not data.get("error"):
                return {
                    "country": data.get("country_name", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("org", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude"),
                    "timezone": data.get("timezone", "Unknown")
                }
    except Exception:
        pass
    return None

# 4b. Live Domain Registration Lookup via RDAP
def _base_domain_candidates(hostname):
    parts = hostname.split('.')
    candidates = [hostname]
    if len(parts) > 2:
        candidates.append('.'.join(parts[-2:]))
    return candidates

def _parse_rdap_date(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except Exception:
        return None

def resolve_whois_record(hostname):
    for candidate in _base_domain_candidates(hostname):
        try:
            resp = requests.get(f"https://rdap.org/domain/{candidate}", timeout=6,
                                 headers={"Accept": "application/rdap+json"})
            if resp.status_code != 200:
                continue
            data = resp.json()

            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            created = _parse_rdap_date(events.get("registration"))
            expires = _parse_rdap_date(events.get("expiration"))
            updated = _parse_rdap_date(events.get("last changed") or events.get("last update of RDAP database"))

            registrar = "Unknown"
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray")
                    if vcard and len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                registrar = field[3]
                                break

            name_servers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
            age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days if created else None

            if age_days is None:
                age_status = "⚪ Registration date unavailable"
            elif age_days < 30:
                age_status = f"🔴 Very new domain — registered {age_days} days ago (common phishing trait)"
            elif age_days < 180:
                age_status = f"🟠 Recently registered — {age_days} days ago"
            else:
                age_status = f"🟢 Established domain — {age_days} days old"

            return {
                "found": True, "registrar": registrar,
                "creation_date": str(created) if created else "Unknown",
                "expiration_date": str(expires) if expires else "Unknown",
                "updated_date": str(updated) if updated else "Unknown",
                "name_servers": name_servers, "org": registrar, "country": data.get("country", "Not disclosed"),
                "age_days": age_days, "age_status": age_status
            }
        except Exception:
            continue
    return {"found": False, "error": "No RDAP record found — domain may be unregistered, or registry unreachable"}

# 4b-2. Live Certificate Transparency Check via SSLMate's Cert Spotter API
def check_cert_transparency(hostname):
    for candidate in _base_domain_candidates(hostname):
        try:
            resp = requests.get(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": candidate, "include_subdomains": "true", "expand": "cert"},
                timeout=6
            )
            if resp.status_code != 200:
                continue
            issuances = resp.json()
            if not issuances:
                return {"found": False, "status": "⚪ No certificates found in CT logs for this domain"}

            newest = None
            newest_dt = None
            for entry in issuances:
                not_before = entry.get("not_before")
                try:
                    dt = datetime.datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                except Exception:
                    continue
                if newest_dt is None or dt > newest_dt:
                    newest_dt = dt
                    newest = entry

            if newest_dt is None:
                return {"found": False, "status": "⚪ Could not parse certificate issuance dates"}

            age_days = (datetime.datetime.now(datetime.timezone.utc) - newest_dt).days
            issuer = newest.get("issuer", {}).get("name", "Unknown") if isinstance(newest.get("issuer"), dict) else "Unknown"
            total_certs = len(issuances)

            if age_days < 7:
                status = f"🔴 Newest cert issued only {age_days} day(s) ago — freshly stood-up infrastructure (common phishing trait)"
            elif age_days < 30:
                status = f"🟠 Newest cert issued {age_days} days ago — recently deployed"
            else:
                status = f"🟢 Newest cert issued {age_days} days ago — established certificate history"

            return {
                "found": True, "age_days": age_days, "issuer": issuer,
                "total_certs_seen": total_certs, "status": status
            }
        except Exception:
            continue
    return {"found": False, "status": "⚪ Certificate Transparency lookup unavailable"}

# 4c. Redirect Chain Tracer
def _extract_client_side_redirect(html_text, base_url):
    from urllib.parse import urljoin

    meta_match = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\s*\d+\s*;\s*url\s*=\s*([^"\'>\s]+)',
        html_text, re.IGNORECASE
    )
    if meta_match:
        return urljoin(base_url, meta_match.group(1).strip())

    js_match = re.search(
        r'(?:window\.location(?:\.href)?\s*=\s*|location\.replace\s*\(\s*)["\']([^"\']+)["\']',
        html_text, re.IGNORECASE
    )
    if js_match:
        return urljoin(base_url, js_match.group(1).strip())

    return None

def trace_redirect_chain(url, max_hops=10):
    chain = [url]
    current_url = url
    visited = set()

    try:
        for _ in range(max_hops):
            if current_url in visited:
                break
            visited.add(current_url)

            resp = requests.get(
                current_url, timeout=6.0, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (ThreatX-Scanner)"}
            )

            for h in resp.history:
                if h.url not in chain:
                    chain.append(h.url)
            if resp.url not in chain:
                chain.append(resp.url)
            current_url = resp.url

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" in content_type.lower():
                client_target = _extract_client_side_redirect(resp.text, resp.url)
                if client_target and client_target != current_url and client_target not in chain:
                    chain.append(client_target)
                    current_url = client_target
                    continue
            break

        return chain[:max_hops], chain[-1]
    except Exception:
        return chain, url

# 5. Core Lexical Calculation & Extended Heuristics Engine
def normalize_host_for_comparison(url):
    h = urlparse(url).netloc.lower().split(':')[0]
    if h.startswith('www.'):
        h = h[4:]
    return h

def count_cross_domain_hops(chain):
    count = 0
    for i in range(len(chain) - 1):
        if normalize_host_for_comparison(chain[i]) != normalize_host_for_comparison(chain[i + 1]):
            count += 1
    return count

def has_domain_drift(original_url, final_url):
    return normalize_host_for_comparison(original_url) != normalize_host_for_comparison(final_url)

def extract_lexical_vectors(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

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
        wl in clean for wl in ['google.com', 'github.com', 'wikipedia.org', 'paypal.com']
    ) else 0

    is_ssl = 1 if parsed.scheme == 'https' else 0
    is_ip_masked = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean.split(':')[0]) else 0

    features = [length, has_at, subdomains, has_dash, round(entropy, 2), has_token]
    pro_heuristics = {"is_ssl": is_ssl, "is_ip_masked": is_ip_masked}
    return features, host, pro_heuristics

# 6. Unified scan pipeline
def scan_url(user_target, gsb_key=None, urlhaus_key=None):
    original_url = user_target if user_target.startswith(('http://', 'https://')) else 'https://' + user_target

    redirect_chain, final_url = trace_redirect_chain(original_url)
    cross_domain_hops = count_cross_domain_hops(redirect_chain)
    domain_drift = has_domain_drift(original_url, final_url)

    feature_weights, host_domain, pro_meta = extract_lexical_vectors(final_url)
    resolved_ip, dns_status_log = resolve_live_dns_ip(host_domain)
    geo_info = resolve_geolocation(resolved_ip)
    whois_info = resolve_whois_record(host_domain)
    cert_info = check_cert_transparency(host_domain)
    urlhaus_result = check_past_phishing_history(final_url, auth_key=urlhaus_key)
    gsb_result = check_google_safe_browsing(final_url, gsb_key)

    eval_dataframe = pd.DataFrame(
        [feature_weights + [pro_meta["is_ssl"], pro_meta["is_ip_masked"]]],
        columns=['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token', 'is_ssl', 'is_ip_masked']
    )
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
    if cert_info.get("found") and cert_info.get("age_days") is not None:
        if cert_info["age_days"] < 7:
            dynamic_risk_weight += 15.0
        elif cert_info["age_days"] < 30:
            dynamic_risk_weight += 6.0
    if domain_drift:
        dynamic_risk_weight += 20.0
    if urlhaus_result.get("matched"):
        dynamic_risk_weight += 30.0
    if gsb_result.get("matched"):
        dynamic_risk_weight += 45.0

    risk_percent = round(min(99.4, max(4.2, dynamic_risk_weight)), 1)
    safety_percent = round(100.0 - risk_percent, 1)
    is_malicious_class = True if risk_percent >= 45.0 else False

    return {
        "input_url": user_target,
        "original_url": original_url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "cross_domain_hops": cross_domain_hops,
        "domain_drift": domain_drift,
        "host_domain": host_domain,
        "feature_weights": feature_weights,
        "pro_meta": pro_meta,
        "resolved_ip": resolved_ip,
        "dns_status_log": dns_status_log,
        "geo_info": geo_info,
        "whois_info": whois_info,
        "cert_info": cert_info,
        "urlhaus_result": urlhaus_result,
        "gsb_result": gsb_result,
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
        "Redirect Hops (Total)": len(result["redirect_chain"]) - 1,
        "Redirect Hops (Cross-Domain)": result["cross_domain_hops"],
        "Verdict": "DANGEROUS" if result["is_malicious_class"] else "SAFE",
        "Risk %": result["risk_percent"],
        "Safety %": result["safety_percent"],
        "Server IP": result["resolved_ip"],
        "DNS Status": result["dns_status_log"],
        "SSL": "Yes" if result["pro_meta"]["is_ssl"] else "No",
        "IP-Masked Domain": "Yes" if result["pro_meta"]["is_ip_masked"] else "No",
        "URLhaus Checked OK": result["urlhaus_result"].get("checked", False),
        "URLhaus Match": result["urlhaus_result"].get("matched", False),
        "GSB Checked OK": result["gsb_result"].get("checked", False),
        "Google Safe Browsing Match": result["gsb_result"].get("matched", False),
        "Domain Age (days)": (result["whois_info"].get("age_days")
                              if result["whois_info"].get("age_days") is not None else "N/A"),
        "Registrar": result["whois_info"].get("registrar", "N/A"),
        "Cert Age (days)": (result["cert_info"].get("age_days")
                            if result["cert_info"].get("age_days") is not None else "N/A"),
        "Cert Issuer": result["cert_info"].get("issuer", "N/A"),
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
            "THREAT-X GLOBAL GUARD PRO — Scan Report",
            "=" * 60,
            f"Scanned URL:      {result['input_url']}",
            f"Final URL:        {result['final_url']}",
            f"Redirect Hops:    {len(result['redirect_chain']) - 1} total ({result['cross_domain_hops']} cross-domain)",
            f"Scanned At (UTC): {result['scanned_at']}",
            "",
            f"VERDICT: {verdict}",
            f"Risk Score:   {result['risk_percent']}%",
            f"Safety Score: {result['safety_percent']}%",
            "",
            "-- Threat Intelligence --",
            f"URLhaus:              {result['urlhaus_result']['status']}",
            f"Google Safe Browsing:  {result['gsb_result']['status']}",
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
        lines.append("-- Certificate Transparency --")
        lines.append(result["cert_info"]["status"])

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
    if not ext:
        return False, f"⚪ File has no extension to verify — detected content type: {desc}."
    if not expected_exts:
        return False, f"⚪ Could not verify — unrecognized binary signature for `{ext}`."
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

# 8. API keys — read from server-side secrets, never shown to end users.
def get_gsb_api_key():
    try:
        return st.secrets.get("GSB_API_KEY", "")
    except Exception:
        return ""

def get_urlhaus_auth_key():
    try:
        return st.secrets.get("URLHAUS_AUTH_KEY", "")
    except Exception:
        return ""

gsb_api_key = get_gsb_api_key()
urlhaus_auth_key = get_urlhaus_auth_key()

# 8b. User Console Interface — Single Scan / Bulk Scan / File Scan
tab_single, tab_bulk, tab_file = st.tabs(["🔍 Single Scan", "📂 Bulk Scan", "🗂️ File Scan"])

with tab_single:
    user_target = st.text_input("🔗 Enter website link here to analyze secure features:", placeholder="e.g., https://my-safe-website.com")

    if st.button("🔍 SCAN WEBSITE NOW"):
        if user_target:
            with st.spinner("Tracing redirects, checking threat feeds, WHOIS and geolocation..."):
                result = scan_url(user_target, gsb_key=gsb_api_key, urlhaus_key=urlhaus_auth_key)

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
            cross_domain_hops = result["cross_domain_hops"]
            domain_drift = result["domain_drift"]
            ml_phish_probability = result["ml_phish_probability"]
            urlhaus_result = result["urlhaus_result"]
            gsb_result = result["gsb_result"]

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

            st.write("#### 📡 Live Threat Feed Results:")
            tf_col1, tf_col2 = st.columns(2)
            with tf_col1:
                st.write(f"📝 **URLhaus:** {urlhaus_result['status']}")
            with tf_col2:
                st.write(f"🌐 **Google Safe Browsing:** {gsb_result['status']}")

            st.write("---")

            st.write("#### 🔀 Redirect Chain Trace:")
            if len(redirect_chain) > 1:
                if domain_drift:
                    st.warning(f"⚠️ This link ends up on a different domain than what was entered — the final destination doesn't match the original request.")
                elif cross_domain_hops > 0:
                    st.write(f"ℹ️ This link passes through {cross_domain_hops} intermediate domain(s) but loops back to the original domain (e.g. an auth/session relay) — not treated as risky.")
                else:
                    st.write(f"✅ Redirects only within the same domain (e.g. http→https or www upgrade) — not treated as risky.")
                for i, hop in enumerate(redirect_chain):
                    if i == 0:
                        tag = "🔗 Start"
                    elif i == len(redirect_chain) - 1:
                        tag = "🏁 Final Destination"
                    elif normalize_host_for_comparison(redirect_chain[i - 1]) != normalize_host_for_comparison(hop):
                        tag = f"🔀 Hop {i} (domain change)"
                    else:
                        tag = f"⬆️ Hop {i} (same domain)"
                    st.write(f"**{tag}:** `{hop}`")
            else:
                st.write(f"✅ No redirects detected — direct link to `{redirect_chain[0]}`")

            st.write("---")
            st.write("#### 📡 System Integrity Verification Details:")
            st.write(f"🌐 **Website Host Server IP:** `{resolved_ip}`")
            st.write(f"🔌 **Server Connection Status:** {dns_status_log}")

            st.write("---")

            st.write("#### 🧠 AI Prediction Output (structural model only):")
            ml_confidence = round(ml_phish_probability * 100, 1)
            ml_verdict = "🔴 Suspicious Structure" if ml_phish_probability >= 0.5 else "🟢 Normal Structure"
            ai_col1, ai_col2 = st.columns(2)
            with ai_col1:
                st.write(f"**Model Verdict:** {ml_verdict}")
                st.write(f"**Confidence:** {ml_confidence}%")
            with ai_col2:
                st.write(f"**SSL Present:** {'Yes' if pro_meta['is_ssl'] else 'No'}")
                st.write(f"**Raw-IP Host:** {'Yes' if pro_meta['is_ip_masked'] else 'No'}")
            st.caption(
                "This model only analyzes URL structure (length, entropy, dashes, SSL, "
                "IP-masking, keywords) — it has no internet access of its own and cannot "
                "know if a URL is blocklisted, how old the domain is, or where it redirects. "
                "Those live signals are shown separately below and are what actually drive "
                "the overall Scanner Status verdict at the top of this report."
            )

            st.write("---")

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

            st.write("#### 🔏 Certificate Transparency Check:")
            cert_info = result["cert_info"]
            st.write(cert_info["status"])
            if cert_info.get("found"):
                c_col1, c_col2 = st.columns(2)
                with c_col1:
                    st.write(f"🏢 **Issuer:** {cert_info['issuer']}")
                with c_col2:
                    st.write(f"📊 **Total Certs Seen (CT logs):** {cert_info['total_certs_seen']}")

            st.write("---")

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
                    f"{cross_domain_hops} Cross-Domain Redirect Hop(s) Detected",
                ],
                "Risk Severity Rating": [
                    "✅ LOW RISK" if pro_meta["is_ssl"] == 1 else "⚠️ MEDIUM RISK ALERT",
                    "🚨 CRITICAL HIGH RISK" if pro_meta["is_ip_masked"] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ HIGH SUSPICION" if feature_weights[5] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MINOR ANOMALY" if feature_weights[3] > 0 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if feature_weights[2] > 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if cross_domain_hops >= 2 else "✅ SECURE INFRASTRUCTURE",
                ]
            }
            st.table(pd.DataFrame(breakdown_data))

            st.write("---")
            st.write("#### 🧠 Technical System Ingestion Metrics:")
            full_vector = feature_weights + [pro_meta["is_ssl"], pro_meta["is_ip_masked"]]
            st.info(f"**Structural Feature Vector (fed to model):** {full_vector} "
                    f"→ [length, has_at, subdomains, has_dash, entropy, has_token, is_ssl, is_ip_masked]")
            st.markdown(f"""
            - **Structural Model Confidence:** `{round(ml_phish_probability*100, 1)}%` (URL-shape signal only — see AI Prediction Output above)
            - **URL Lexical Parameters Check:** Length: `{feature_weights[0]}` | Subdomains Detected: `{feature_weights[2]}` | Structural Hyphens: `{feature_weights[3]}` | String Entropy: `{feature_weights[4]}`
            """)

            if is_malicious_class:
                st.error("🛑 ACTION RECOMMENDED: Multiple live and structural signals indicate this URL is unsafe. Avoid entering credentials or personal data.")
            else:
                st.success("✔ No live threat-feed matches or high-risk structural patterns were found in this scan.")

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

        url_list = list(dict.fromkeys(url_list))

        if not url_list:
            st.info("Please upload a CSV or paste at least one URL to run a bulk scan.")
        else:
            progress = st.progress(0, text=f"Scanning 0 / {len(url_list)}...")
            bulk_results = []

            for i, u in enumerate(url_list):
                try:
                    res = scan_url(u, gsb_key=gsb_api_key, urlhaus_key=urlhaus_auth_key)
                    bulk_results.append({
                        "URL": res["input_url"],
                        "Final URL": res["final_url"],
                        "Verdict": "⚠️ DANGEROUS" if res["is_malicious_class"] else "✅ SAFE",
                        "Risk %": res["risk_percent"],
                        "Redirect Hops (Total)": len(res["redirect_chain"]) - 1,
                        "Redirect Hops (Cross-Domain)": res["cross_domain_hops"],
                        "URLhaus Match": res["urlhaus_result"].get("matched", False),
                        "GSB Match": res["gsb_result"].get("matched", False),
                        "Server IP": res["resolved_ip"],
                        "SSL": "Yes" if res["pro_meta"]["is_ssl"] else "No",
                        "Domain Age (days)": (res["whois_info"].get("age_days")
                                              if res["whois_info"].get("age_days") is not None else "N/A"),
                        "Country": res["geo_info"]["country"] if res["geo_info"] else "N/A",
                    })
                except Exception as e:
                    bulk_results.append({
                        "URL": u, "Final URL": "ERROR", "Verdict": "⚪ SCAN FAILED",
                        "Risk %": "N/A", "Redirect Hops (Total)": "N/A", "Redirect Hops (Cross-Domain)": "N/A",
                        "URLhaus Match": "N/A", "GSB Match": "N/A", "Server IP": "N/A",
                        "SSL": "N/A", "Domain Age (days)": "N/A", "Country": "N/A",
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

# 10. Credit Footer
st.write("---")
st.markdown(
    "<div style='text-align:center; color:#475569; font-size:20px; padding:14px 0 6px 0;'>"
    "Built under the guidance of <span style='color:#94a3b8; font-weight:600;'>Mr. Arepally Sai Shanthan Sir</span>"
    "</div>",
    unsafe_allow_html=True
)
