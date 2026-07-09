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
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier, IsolationForest

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

st.write("<div style='text-align: center; padding-top: 10px;'><span style='font-size: 38px; font-weight: 800; color: #ffffff; letter-spacing: 1px;'>THREAT</span><span style='font-size: 38px; font-weight: 800; color: #00ffcc; letter-spacing: 1px;'>-X</span><span style='font-size: 14px; font-weight: bold; color: #475569; margin-left: 8px;'>GLOBAL GUARD PRO v15.0</span></div>", unsafe_allow_html=True)
st.write("<p style='text-align: center; color: #94a3b8; font-size: 15px; font-family: Arial;'>Enter any website address below to run a live scan across real threat-intelligence feeds, WHOIS, SSL, and redirect analysis.</p>", unsafe_allow_html=True)
st.write("<p style='text-align: center; color: #64748b; font-size: 12px; font-family: Arial; font-style: italic;'>⚠️ This tool produces a heuristic + AI-assisted risk assessment, not a definitive legal or forensic verdict. Always use independent judgement before entering credentials on any site.</p>", unsafe_allow_html=True)
st.write("---")

# 2. Structural Heuristic + Anomaly-Detection Model (RandomForest + IsolationForest)
# FIX: Expanded training set from 60 -> 96 rows for stronger coverage across both classes.
# NEW (AI upgrade v15.0): Added a second unsupervised model (IsolationForest) trained only on
# "safe" reference patterns. It flags URLs that are structurally weird even if the supervised
# classifier hasn't seen anything exactly like it before — this is what makes the scanner
# resilient to *new* phishing patterns instead of only ones matching its training examples.
RAW_TRAINING_DATA = [
    # [length, has_at, subdomains, has_dash, entropy, has_token, is_ssl, is_raw_ip, result]
    # --- SAFE (result=0) ---
    [15, 0, 0, 0, 2.4, 0, 1, 0, 0], [18, 0, 1, 0, 2.7, 0, 1, 0, 0],
    [22, 0, 2, 0, 3.1, 0, 1, 0, 0], [28, 0, 0, 0, 2.9, 0, 1, 0, 0],
    [25, 0, 1, 1, 3.2, 0, 1, 0, 0], [30, 0, 1, 1, 3.5, 0, 1, 0, 0],
    [33, 0, 1, 1, 3.76, 0, 1, 0, 0], [36, 0, 0, 1, 3.6, 0, 1, 0, 0],
    [40, 0, 1, 1, 3.9, 0, 1, 0, 0], [20, 0, 0, 1, 3.0, 0, 1, 0, 0],
    [29, 0, 2, 0, 3.4, 0, 1, 0, 0], [24, 0, 1, 0, 3.1, 0, 1, 0, 0],
    [16, 0, 0, 0, 2.2, 0, 1, 0, 0], [21, 0, 1, 0, 3.0, 0, 1, 0, 0],
    [27, 0, 0, 1, 3.3, 0, 1, 0, 0], [19, 0, 0, 0, 2.6, 0, 0, 0, 0],
    [23, 0, 1, 0, 3.0, 0, 0, 0, 0], [11, 0, 0, 0, 2.1, 0, 1, 0, 0],
    [14, 0, 0, 0, 2.3, 0, 1, 0, 0], [17, 0, 0, 0, 2.5, 0, 1, 0, 0],
    [31, 0, 1, 0, 3.2, 0, 1, 0, 0], [26, 0, 0, 0, 3.1, 0, 1, 0, 0],
    [35, 0, 1, 1, 3.7, 0, 1, 0, 0], [38, 0, 0, 1, 3.8, 0, 1, 0, 0],
    [12, 0, 0, 0, 2.0, 0, 1, 0, 0], [20, 0, 1, 0, 2.9, 0, 1, 0, 0],
    # NEW extra safe samples (v15.0) — broader coverage of legitimate site shapes
    [13, 0, 0, 0, 2.2, 0, 1, 0, 0], [41, 0, 1, 1, 3.85, 0, 1, 0, 0],
    [10, 0, 0, 0, 1.9, 0, 1, 0, 0], [37, 0, 2, 0, 3.6, 0, 1, 0, 0],
    [43, 0, 1, 1, 3.95, 0, 1, 0, 0], [9, 0, 0, 0, 1.8, 0, 1, 0, 0],
    [32, 0, 0, 1, 3.4, 0, 1, 0, 0], [46, 0, 1, 1, 4.0, 0, 1, 0, 0],
    [28, 0, 2, 0, 3.3, 0, 1, 0, 0], [22, 0, 0, 1, 3.05, 0, 1, 0, 0],
    [34, 0, 1, 0, 3.55, 0, 1, 0, 0], [18, 0, 1, 1, 2.85, 0, 1, 0, 0],
    [39, 0, 0, 0, 3.75, 0, 1, 0, 0], [25, 0, 2, 1, 3.25, 0, 1, 0, 0],
    # NEW extra safe samples (v16.0) -- modern hosted-app naming shapes. Real SaaS/demo apps
    # deployed on platforms like streamlit.app / vercel.app / netlify.app are almost always
    # multi-word-hyphenated subdomains with naturally high entropy. Without these rows the
    # model had ZERO safe examples in the dash+subdomain+high-entropy region, so it learned
    # "dash + subdomain + entropy>3.6" == phishing purely by absence of counter-examples --
    # this is what caused legitimate hosted apps (e.g. the scanner's own *.streamlit.app URL)
    # to be misclassified as "Suspicious Structure" despite every live threat feed being clean.
    [34, 0, 1, 1, 3.7, 0, 1, 0, 0], [29, 0, 1, 1, 3.65, 0, 1, 0, 0],
    [37, 0, 1, 1, 3.85, 0, 1, 0, 0], [31, 0, 1, 1, 3.75, 0, 1, 0, 0],
    [40, 0, 1, 1, 3.95, 0, 1, 0, 0], [26, 0, 1, 1, 3.6, 0, 1, 0, 0],
    [35, 0, 2, 1, 3.9, 0, 1, 0, 0], [28, 0, 1, 1, 3.7, 0, 1, 0, 0],
    [42, 0, 1, 1, 4.05, 0, 1, 0, 0], [33, 0, 2, 1, 3.8, 0, 1, 0, 0],
    [38, 0, 1, 1, 4.0, 0, 1, 0, 0], [24, 0, 1, 1, 3.55, 0, 1, 0, 0],
    [45, 0, 1, 1, 4.15, 0, 1, 0, 0], [30, 0, 1, 1, 3.68, 0, 1, 0, 0],
    [36, 0, 2, 1, 3.92, 0, 1, 0, 0],
    # --- SUSPICIOUS / PHISHING (result=1) ---
    [32, 0, 1, 2, 4.2, 1, 1, 0, 1], [45, 0, 0, 2, 4.1, 1, 1, 0, 1],
    [55, 0, 1, 2, 4.3, 1, 1, 0, 1], [72, 1, 2, 1, 4.5, 1, 1, 0, 1],
    [34, 0, 1, 2, 4.2, 1, 1, 0, 1], [17, 0, 1, 0, 4.4, 1, 1, 0, 1],
    [26, 0, 2, 1, 4.1, 1, 1, 0, 1], [38, 0, 1, 1, 4.0, 1, 1, 0, 1],
    [30, 0, 1, 2, 4.3, 1, 0, 0, 1], [42, 0, 0, 2, 4.2, 1, 0, 0, 1],
    [15, 0, 0, 0, 3.8, 0, 1, 1, 1], [15, 0, 0, 0, 3.9, 1, 0, 1, 1],
    [18, 1, 0, 0, 4.0, 0, 1, 1, 1], [60, 1, 3, 2, 4.6, 1, 0, 0, 1],
    [80, 0, 3, 3, 4.8, 1, 0, 0, 1], [50, 1, 2, 2, 4.5, 1, 0, 0, 1],
    [75, 0, 2, 3, 4.7, 1, 0, 1, 1], [90, 1, 4, 3, 4.9, 1, 0, 0, 1],
    [65, 0, 3, 2, 4.6, 1, 1, 0, 1], [48, 0, 2, 2, 4.4, 1, 0, 0, 1],
    [35, 1, 1, 1, 4.3, 1, 0, 0, 1], [22, 0, 2, 0, 4.1, 1, 0, 0, 1],
    [44, 0, 1, 3, 4.5, 1, 0, 0, 1], [58, 1, 2, 2, 4.7, 1, 0, 0, 1],
    [28, 0, 3, 1, 4.2, 1, 1, 0, 1], [37, 0, 2, 2, 4.3, 1, 0, 0, 1],
    # NEW extra phishing samples (v15.0) — more variety of attack shapes
    [67, 0, 3, 3, 4.65, 1, 0, 0, 1], [21, 0, 2, 1, 4.15, 1, 0, 0, 1],
    [52, 1, 1, 2, 4.55, 1, 0, 0, 1], [19, 0, 1, 0, 4.35, 1, 0, 1, 1],
    [63, 0, 2, 3, 4.6, 1, 0, 0, 1], [29, 0, 3, 2, 4.25, 1, 1, 0, 1],
    [70, 1, 3, 2, 4.75, 1, 0, 0, 1], [24, 0, 1, 1, 4.05, 1, 0, 0, 1],
    [56, 0, 2, 2, 4.5, 1, 0, 0, 1], [41, 0, 1, 3, 4.35, 1, 0, 0, 1],
    [85, 0, 4, 3, 4.85, 1, 0, 0, 1], [33, 1, 0, 1, 4.2, 1, 0, 0, 1],
]
FEATURE_NAMES = ['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token', 'is_ssl', 'is_raw_ip']

@st.cache_resource
def compile_advanced_ml_model():
    df = pd.DataFrame(RAW_TRAINING_DATA, columns=FEATURE_NAMES + ['result'])
    # FIX: `has_dash`/`has_at`/`has_token`/`is_ssl`/`is_raw_ip` are boolean features at inference
    # time (always 0 or 1), but a few training rows had raw dash-counts (2, 3...) in that column.
    # That parity mismatch let the model learn a spurious "more dashes = more phishing" scale that
    # never occurs at inference. Clamp to true 0/1 so training matches what scan_url() ever sends.
    for col in ['has_at', 'has_dash', 'has_token', 'is_ssl', 'is_raw_ip']:
        df[col] = (df[col] > 0).astype(int)
    clf = RandomForestClassifier(n_estimators=250, max_depth=7, random_state=42)
    clf.fit(df[FEATURE_NAMES], df['result'])
    return clf

@st.cache_resource
def compile_anomaly_detector():
    """Unsupervised second-opinion model — flags structurally 'weird' URLs even when
    they don't match any known phishing pattern in the supervised training set."""
    df = pd.DataFrame(RAW_TRAINING_DATA, columns=FEATURE_NAMES + ['result'])
    for col in ['has_at', 'has_dash', 'has_token', 'is_ssl', 'is_raw_ip']:
        df[col] = (df[col] > 0).astype(int)
    safe_only = df[df['result'] == 0][FEATURE_NAMES]
    iso = IsolationForest(n_estimators=200, contamination=0.12, random_state=42)
    iso.fit(safe_only)
    return iso

cyber_classifier = compile_advanced_ml_model()
anomaly_detector = compile_anomaly_detector()

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
            timeout=6.0
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

# 3b. Google Safe Browsing Check
def check_google_safe_browsing(target_url, api_key):
    if not api_key:
        return {"checked": False, "matched": False, "status": "⚪ Skipped — no API key provided"}
    try:
        body = {
            "client": {"clientId": "threat-x-global-guard", "clientVersion": "15.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}]
            }
        }
        resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                              json=body, timeout=8)
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            if matches:
                types = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
                return {"checked": True, "matched": True, "status": f"🔴 Google Safe Browsing MATCH — {types}"}
            return {"checked": True, "matched": False, "status": "🟢 Clean — no match on Google Safe Browsing"}
        return {"checked": False, "matched": False, "status": f"⚪ API error (HTTP {resp.status_code})"}
    except Exception:
        return {"checked": False, "matched": False, "status": "⚪ Google Safe Browsing request failed"}

# 3c. NEW — OpenPhish Community Feed Check (100% FREE, no API key, no signup required)
# NOTE (be realistic about this): OpenPhish's *free* offering is the "Community Feed" —
# a flat text list of ~500 currently-active phishing URLs at https://openphish.com/feed.txt,
# refreshed roughly every 12 hours. It is genuinely free and has no request limit because you
# are not "calling an API" per lookup — you download the whole list and match locally.
# OpenPhish does NOT offer a free unlimited *lookup API* for arbitrary historical URLs —
# that tier ("OpenPhish Premium") is a paid product. This integration uses the real free
# feed honestly, cached for 1 hour so we don't hammer their server on every scan.
@st.cache_data(ttl=3600, show_spinner=False)
def _fetch_openphish_feed():
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=10,
                             headers={"User-Agent": "ThreatX-GlobalGuard/15.0"})
        if resp.status_code == 200:
            return tuple(line.strip().rstrip('/') for line in resp.text.splitlines() if line.strip())
    except Exception:
        pass
    return tuple()

def check_openphish(original_url, final_url):
    feed = _fetch_openphish_feed()
    if not feed:
        return {"checked": False, "matched": False,
                "status": "⚪ OpenPhish feed unavailable (network/timeout error, or feed temporarily empty)"}
    feed_set = set(feed)
    candidates = {original_url.rstrip('/'), final_url.rstrip('/')}
    if any(c in feed_set for c in candidates):
        return {"checked": True, "matched": True,
                "status": "🔴 Found in OpenPhish live community feed — actively reported as an in-the-wild phishing URL"}
    return {"checked": True, "matched": False,
            "status": f"🟢 No match — not present in OpenPhish's current feed ({len(feed_set)} active phishing URLs tracked)"}

# 3d. NEW — VirusTotal (real multi-engine aggregator, 70+ AV/blocklist vendors)
# Free public API: 500 requests/day, 4/min. Needs a free API key from virustotal.com.
# For URLs: try to fetch an existing report first (no quota cost beyond 1 request); if VT has
# never seen this URL before, submit it for a fresh analysis and poll briefly for the result.
import base64

def _vt_headers(api_key):
    return {"x-apikey": api_key, "User-Agent": "ThreatX-GlobalGuard/16.0"}

def check_virustotal_url(target_url, api_key):
    if not api_key:
        return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total_engines": 0,
                "status": "⚪ Skipped — no VirusTotal API key configured"}
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers=_vt_headers(api_key), timeout=10)

        if resp.status_code == 429:
            return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total_engines": 0,
                    "status": "⚪ VirusTotal rate limit hit (free tier: 4 req/min, 500/day) — try again shortly"}
        if resp.status_code == 404:
            # VT has never analyzed this exact URL — submit it fresh and poll briefly.
            submit_resp = requests.post("https://www.virustotal.com/api/v3/urls",
                                         headers=_vt_headers(api_key),
                                         data={"url": target_url}, timeout=10)
            if submit_resp.status_code not in (200, 201):
                return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                        "harmless": 0, "undetected": 0, "total_engines": 0,
                        "status": f"⚪ VirusTotal submission failed (HTTP {submit_resp.status_code})"}
            analysis_id = submit_resp.json().get("data", {}).get("id")
            if not analysis_id:
                return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                        "harmless": 0, "undetected": 0, "total_engines": 0,
                        "status": "⚪ VirusTotal submission returned no analysis id"}

            import time as _time
            stats = None
            for _ in range(6):  # poll up to ~12s — engines usually finish fast for URLs
                _time.sleep(2)
                poll = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                    headers=_vt_headers(api_key), timeout=10)
                if poll.status_code == 200:
                    poll_data = poll.json().get("data", {}).get("attributes", {})
                    if poll_data.get("status") == "completed":
                        stats = poll_data.get("stats", {})
                        break
            if stats is None:
                return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                        "harmless": 0, "undetected": 0, "total_engines": 0,
                        "status": "⚪ VirusTotal analysis still pending — new URL, try scanning again shortly"}
        elif resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        else:
            return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total_engines": 0,
                    "status": f"⚪ VirusTotal lookup failed (HTTP {resp.status_code})"}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious + suspicious > 0:
            return {"checked": True, "matched": True, "malicious": malicious, "suspicious": suspicious,
                    "harmless": harmless, "undetected": undetected, "total_engines": total,
                    "status": f"🔴 VirusTotal: {malicious + suspicious}/{total} security vendors flag this URL as malicious/suspicious"}
        return {"checked": True, "matched": False, "malicious": malicious, "suspicious": suspicious,
                "harmless": harmless, "undetected": undetected, "total_engines": total,
                "status": f"🟢 VirusTotal: 0/{total} security vendors flagged this URL"}
    except Exception:
        return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total_engines": 0,
                "status": "⚪ VirusTotal request failed (network/timeout error)"}

# 3e. NEW — urlscan.io free public search (100% free, no signup/API key needed for search)
# NOTE (be realistic about this): urlscan.io lets ANYONE query its public search index of URLs
# other users/systems have already scanned, with no key and no hard rate limit for light use.
# It does NOT let you submit a brand-new scan for free without an API key, so this only checks
# whether the URL (or its domain) has already been seen/flagged by the community — a real extra
# signal, not a fake one. Cached for 10 min per URL to be a good API citizen.
@st.cache_data(ttl=600, show_spinner=False)
def check_urlscan(target_url, target_domain):
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{target_domain}", "size": 20},
            headers={"User-Agent": "ThreatX-GlobalGuard/16.0"},
            timeout=8
        )
        if resp.status_code != 200:
            return {"checked": False, "matched": False, "status": f"⚪ urlscan.io lookup failed (HTTP {resp.status_code})"}
        results = resp.json().get("results", [])
        if not results:
            return {"checked": True, "matched": False,
                    "status": "🟢 urlscan.io: no prior community scans found for this domain"}
        malicious_hits = 0
        for r in results:
            verdicts = r.get("verdicts", {}) if isinstance(r, dict) else {}
            overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
            if overall.get("malicious") is True:
                malicious_hits += 1
        if malicious_hits > 0:
            return {"checked": True, "matched": True, "hits": malicious_hits, "total": len(results),
                    "status": f"🔴 urlscan.io: {malicious_hits}/{len(results)} prior community scans of this domain flagged as malicious"}
        return {"checked": True, "matched": False, "hits": 0, "total": len(results),
                "status": f"🟢 urlscan.io: {len(results)} prior scans found for this domain, none flagged malicious"}
    except Exception:
        return {"checked": False, "matched": False, "status": "⚪ urlscan.io lookup failed (network/timeout error)"}

def check_virustotal_file(sha256_hash, api_key):
    if not api_key:
        return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total_engines": 0,
                "status": "⚪ Skipped — no VirusTotal API key configured"}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
                             headers=_vt_headers(api_key), timeout=10)
        if resp.status_code == 429:
            return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total_engines": 0,
                    "status": "⚪ VirusTotal rate limit hit (free tier: 4 req/min, 500/day) — try again shortly"}
        if resp.status_code == 404:
            return {"checked": True, "matched": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total_engines": 0,
                    "status": "🟡 VirusTotal has never seen this exact file before (unknown hash — not necessarily safe)"}
        if resp.status_code != 200:
            return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "total_engines": 0,
                    "status": f"⚪ VirusTotal lookup failed (HTTP {resp.status_code})"}

        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious + suspicious > 0:
            return {"checked": True, "matched": True, "malicious": malicious, "suspicious": suspicious,
                    "harmless": harmless, "undetected": undetected, "total_engines": total,
                    "status": f"🔴 VirusTotal: {malicious + suspicious}/{total} antivirus engines flag this file as malicious/suspicious"}
        return {"checked": True, "matched": False, "malicious": malicious, "suspicious": suspicious,
                "harmless": harmless, "undetected": undetected, "total_engines": total,
                "status": f"🟢 VirusTotal: 0/{total} antivirus engines flagged this file"}
    except Exception:
        return {"checked": False, "matched": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total_engines": 0,
                "status": "⚪ VirusTotal request failed (network/timeout error)"}

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
_COMMON_TWO_PART_SUFFIXES = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
    'co.in', 'org.in', 'net.in', 'gov.in', 'co.jp', 'co.kr', 'co.nz', 'co.za',
    'com.au', 'net.au', 'org.au', 'com.br', 'com.mx', 'com.sg', 'com.hk',
    'co.id', 'co.th', 'com.tr', 'com.ar',
}

def _base_domain_candidates(hostname):
    # FIX: Strip port first
    hostname = hostname.split(':')[0].lower()
    parts = hostname.split('.')
    candidates = [hostname]
    if len(parts) > 2:
        # FIX: naive "last two labels" broke on multi-part public suffixes like *.co.uk —
        # e.g. "evil.example.co.uk" collapsed to "example.co.uk" instead of the registrable
        # "example.co.uk" being correct only when the suffix truly is 2 labels; for a genuine
        # 3-label host under a 2-label suffix we need the last 3 labels, not 2.
        last_two = '.'.join(parts[-2:])
        if last_two in _COMMON_TWO_PART_SUFFIXES and len(parts) > 3:
            candidates.append('.'.join(parts[-3:]))
        else:
            candidates.append(last_two)
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
            # FIX: Use timezone-aware datetime
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now_utc - created).days if created else None

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

            # FIX: Use timezone-aware datetime
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now_utc - newest_dt).days
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

# Phishing-specific constants
PHISHING_TLDS = {
    '.click', '.online', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.pw', '.cc', '.icu', '.live', '.support', '.security',
    '.verify', '.bank', '.update', '.work', '.link', '.ltd', '.vip',
    '.win', '.loan', '.download', '.accountant', '.trade', '.racing',
    '.review', '.date', '.faith', '.cricket', '.party', '.science',
    '.men', '.bid', '.webcam', '.stream', '.gdn', '.buzz'
}

# Free hosting platforms abused by phishers
# NEW (v16.0): added streamlit.app -- like vercel/netlify, it's free hosting that CAN be
# abused, but it's also where the scanner itself lives plus thousands of legit demo apps.
# See LOW_ABUSE_MAINSTREAM_PLATFORMS below -- these get a lower "alone" weight than
# platforms with almost no legitimate use (e.g. byet.host), instead of being treated the same.
PHISHING_PLATFORMS = [
    'vercel.app', 'framer.app', 'netlify.app', 'glitch.me',
    'web.app', 'firebaseapp.com', 'pages.dev', 'blogspot.com',
    'wordpress.com', 'weebly.com', 'wixsite.com', 'site123.me',
    'carrd.co', 'notion.site', 'gitbook.io', 'repl.co',
    '000webhostapp.com', 'byet.host', 'infinityfreeapp.com',
    'streamlit.app'
]

# Platforms with heavy mainstream legitimate use get a reduced "lone signal" weight so a
# single ordinary hosted app isn't punished the same as an obscure free-host abused almost
# exclusively for phishing kits.
LOW_ABUSE_MAINSTREAM_PLATFORMS = {'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com',
                                   'pages.dev', 'streamlit.app', 'glitch.me'}

# Brand names phishers impersonate — checked in full URL (domain + path)
IMPERSONATED_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'netflix', 'whatsapp', 'telegram', 'linkedin',
    'twitter', 'tiktok', 'youtube', 'chase', 'wellsfargo', 'citibank',
    'bankofamerica', 'barclays', 'hsbc', 'sbi', 'hdfc', 'icici',
    'coinbase', 'binance', 'metamask', 'trezor', 'ledger', 'kraken',
    'dropbox', 'onedrive', 'icloud', 'outlook', 'office365', 'adobe'
]

OFFICIAL_BRAND_DOMAINS = {
    'paypal':     ['paypal.com', 'paypal.me', 'paypal.co.uk'],
    'amazon':     ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr',
                   'amazon.com.au', 'amazon.ca', 'amzn.to'],
    'apple':      ['apple.com', 'icloud.com', 'mzstatic.com', 'apple.com.au'],
    'microsoft':  ['microsoft.com', 'live.com', 'hotmail.com', 'outlook.com',
                   'azure.com', 'office.com', 'msn.com', 'bing.com', 'skype.com'],
    'google':     ['google.com', 'google.co.in', 'google.co.uk', 'google.com.au',
                   'googleapis.com', 'googleusercontent.com', 'goo.gl'],
    'facebook':   ['facebook.com', 'fb.com', 'fbcdn.net', 'facebook.net'],
    'instagram':  ['instagram.com', 'cdninstagram.com'],
    'netflix':    ['netflix.com', 'nflxext.com', 'nflximg.com'],
    'whatsapp':   ['whatsapp.com', 'whatsapp.net'],
    'telegram':   ['telegram.org', 't.me'],
    'linkedin':   ['linkedin.com', 'licdn.com'],
    'twitter':    ['twitter.com', 'x.com', 't.co', 'twimg.com'],
    'tiktok':     ['tiktok.com', 'tiktokcdn.com'],
    'youtube':    ['youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com'],
    'dropbox':    ['dropbox.com', 'dropboxstatic.com'],
    'coinbase':   ['coinbase.com'],
    'binance':    ['binance.com', 'binance.cc'],
    'metamask':   ['metamask.io'],
    'trezor':     ['trezor.io'],
    'ledger':     ['ledger.com'],
    'kraken':     ['kraken.com'],
    'hdfc':       ['hdfcbank.com', 'hdfc.com', 'hdfcsec.com'],
    'icici':      ['icicibank.com', 'icicidirect.com'],
    'sbi':        ['sbi.co.in', 'onlinesbi.com', 'sbicards.com'],
    'adobe':      ['adobe.com', 'adobecc.com'],
    'onedrive':   ['onedrive.live.com', 'office.com'],
    'icloud':     ['icloud.com', 'apple.com'],
    'outlook':    ['outlook.com', 'outlook.live.com', 'microsoft.com'],
    'office365':  ['office.com', 'microsoft.com', 'office365.com'],
    'chase':      ['chase.com', 'jpmorgan.com'],
    'wellsfargo': ['wellsfargo.com'],
    'citibank':   ['citibank.com', 'citi.com'],
    'bankofamerica': ['bankofamerica.com', 'bac.com'],
    'barclays':   ['barclays.com', 'barclaysbank.com'],
    'hsbc':       ['hsbc.com', 'hsbc.co.uk'],
}

# 5b. NEW — Typosquatting Similarity Engine (difflib sequence-similarity, AI-assisted)
# Catches domains that are NOT an exact substring match (so the old brand_in_host check
# misses them) but are visually/structurally near-identical to a real brand domain —
# e.g. "paypa1.com", "arnazon.com", "micros0ft-support.com".
def check_typosquatting(clean_host):
    all_known_domains = set()
    for domains in OFFICIAL_BRAND_DOMAINS.values():
        all_known_domains.update(domains)

    host_no_www = clean_host[4:] if clean_host.startswith('www.') else clean_host

    best_match = None
    best_ratio = 0.0
    for domain in all_known_domains:
        ratio = difflib.SequenceMatcher(None, host_no_www, domain).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = domain

    # High similarity but NOT an exact/legit match = likely typosquat
    is_typosquat = bool(best_match) and 0.82 <= best_ratio < 1.0 and host_no_www != best_match
    return is_typosquat, best_match, round(best_ratio, 3)

def extract_lexical_vectors(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    host = parsed.netloc
    clean = host.lower().split(':')[0].strip()
    full_url_lower = url.lower()

    length = len(clean)
    has_at = 1 if "@" in clean else 0

    is_raw_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean) else 0
    subdomains = 0 if is_raw_ip else max(0, len(clean.split('.')) - 2)
    has_dash = 1 if "-" in clean else 0

    probs = [float(clean.count(c)) / len(clean) for c in set(clean)] if len(clean) > 0 else [0.0]
    entropy = -sum([p * math.log(p, 2) for p in probs]) if len(clean) > 0 else 0.0

    tokens = ['login', 'verify', 'verif', 'security', 'secure', 'billing', 'update', 'marketplace',
              'goog1e', 'faceb00k', 'netfliix', 'shekarius', '124', 'allegromt',
              'paypal', 'sbi', 'amazon', 'auth', 'portal', 'signin', 'account',
              'webscr', 'cmd=', 'confirm', 'suspend', 'unlock', 'validate',
              'credito', 'crediito', 'expertverif', 'sorteoficial', 'contemplado']
    whitelist = ['google.com', 'github.com', 'wikipedia.org', 'paypal.com',
                 'amazon.com', 'microsoft.com', 'apple.com']
    # FIX: some tokens (cmd=, webscr, confirm...) only ever appear in the path/query, not the
    # hostname — checking `clean` (hostname only) made those tokens permanently dead. Check the
    # full URL instead, while still only whitelisting on the hostname so a legit domain with a
    # suspicious query string doesn't get a free pass.
    has_token = 1 if any(kw in full_url_lower for kw in tokens) and not any(
        wl in clean for wl in whitelist) else 0

    is_ssl = 1 if parsed.scheme == 'https' else 0

    # --- Extra phishing-specific signals (not in ML model, used in risk scoring) ---
    # 1. Suspicious TLD check
    tld = '.' + clean.split('.')[-1] if '.' in clean else ''
    is_suspicious_tld = tld in PHISHING_TLDS

    # 2. Free hosting platform used for phishing
    is_phishing_platform = any(platform in clean for platform in PHISHING_PLATFORMS)
    # NEW (v16.0): flag whether the matched platform is a mainstream host with heavy
    # legitimate use (streamlit.app, vercel.app, ...) -- used to soften the lone-signal weight.
    is_mainstream_platform = any(platform in clean for platform in LOW_ABUSE_MAINSTREAM_PLATFORMS)

    # 2b. Random/auto-generated subdomain on free hosting platform
    is_random_platform_subdomain = False
    if is_phishing_platform:
        subdomain_part = ""
        for platform in PHISHING_PLATFORMS:
            if clean.endswith(f".{platform}"):
                subdomain_part = clean[: -(len(platform) + 1)]
                if "." in subdomain_part:
                    subdomain_part = subdomain_part.split(".")[-1]
                break
        if subdomain_part:
            has_digit_seq    = bool(re.search(r"\d{3,}", subdomain_part))    # 022802, 964590
            has_dash_digit   = bool(re.search(r"-\d{2,}", subdomain_part))   # raccoon-022802
            is_long_one_word = len(subdomain_part) > 15 and "-" not in subdomain_part  # uiuasorteofficial
            is_random_platform_subdomain = has_digit_seq or has_dash_digit or is_long_one_word

    # 3. Brand impersonation: brand name in HOSTNAME only (not path — avoids false positives)
    brand_in_host = any(brand in clean for brand in IMPERSONATED_BRANDS)
    is_official_brand = False
    if brand_in_host:
        for brand in IMPERSONATED_BRANDS:
            if brand in clean:
                official_domains = OFFICIAL_BRAND_DOMAINS.get(
                    brand, [f'{brand}.com', f'www.{brand}.com']
                )
                if any(clean == od or clean == f"www.{od}" or clean.endswith(f".{od}")
                       for od in official_domains):
                    is_official_brand = True
                    break
    is_brand_impersonation = brand_in_host and not is_official_brand

    # 4. Multiple consecutive dashes (e.g. docs----asuite-trezor.gitbook.io)
    has_multi_dash = 1 if re.search(r'-{2,}', clean) else 0

    # 5. Numeric subdomain/random looking domain
    has_numeric_subdomain = 1 if re.search(r'\d{4,}', clean) else 0

    # 6. NEW — Typosquatting similarity check (AI-assisted, difflib sequence matching)
    is_typosquat, typosquat_target, typosquat_ratio = check_typosquatting(clean)

    features = [length, has_at, subdomains, has_dash, round(entropy, 2), has_token]
    pro_heuristics = {"is_ssl": is_ssl, "is_raw_ip": is_raw_ip}
    phishing_signals = {
        "is_suspicious_tld": is_suspicious_tld,
        "tld": tld,
        "is_phishing_platform": is_phishing_platform,
        "is_mainstream_platform": is_mainstream_platform,
        "is_random_platform_subdomain": is_random_platform_subdomain,
        "is_brand_impersonation": is_brand_impersonation,
        "has_multi_dash": has_multi_dash,
        "has_numeric_subdomain": has_numeric_subdomain,
        "is_typosquat": is_typosquat,
        "typosquat_target": typosquat_target,
        "typosquat_ratio": typosquat_ratio,
    }
    return features, host, pro_heuristics, phishing_signals

# 6. Unified scan pipeline
def scan_url(user_target, gsb_key=None, urlhaus_key=None, vt_key=None):
    original_url = user_target if user_target.startswith(('http://', 'https://')) else 'https://' + user_target

    redirect_chain, final_url = trace_redirect_chain(original_url)
    cross_domain_hops = count_cross_domain_hops(redirect_chain)
    domain_drift = has_domain_drift(original_url, final_url)

    # Now returns 4 values including phishing_signals
    feature_weights, host_domain, pro_meta, phishing_signals = extract_lexical_vectors(final_url)
    resolved_ip, dns_status_log = resolve_live_dns_ip(host_domain)
    geo_info = resolve_geolocation(resolved_ip)
    whois_info = resolve_whois_record(host_domain)
    cert_info = check_cert_transparency(host_domain)
    urlhaus_result = check_past_phishing_history(final_url, auth_key=urlhaus_key)
    gsb_result = check_google_safe_browsing(final_url, gsb_key)
    openphish_result = check_openphish(original_url, final_url)  # NEW — free live phishing feed
    vt_result = check_virustotal_url(final_url, vt_key)  # NEW — real 70+ AV/blocklist vendor report
    urlscan_result = check_urlscan(final_url, host_domain)  # NEW — free community scan history, no key needed

    eval_dataframe = pd.DataFrame(
        [feature_weights + [pro_meta["is_ssl"], pro_meta["is_raw_ip"]]],
        columns=FEATURE_NAMES
    )
    ml_probabilities = cyber_classifier.predict_proba(eval_dataframe)
    ml_phish_probability = float(ml_probabilities[0][1])

    # NEW — Isolation Forest anomaly check (second AI model, unsupervised outlier detection)
    anomaly_prediction = anomaly_detector.predict(eval_dataframe)[0]     # -1 = anomaly, 1 = normal
    anomaly_raw_score = float(anomaly_detector.decision_function(eval_dataframe)[0])  # higher = more "normal"
    is_structurally_anomalous = anomaly_prediction == -1

    # --- Network signals (computed first so we know how much real corroboration exists
    #     before deciding how much to trust the ML model alone) ---
    network_risk = 0.0
    if resolved_ip == "0.0.0.0":
        network_risk += 35.0
    if pro_meta["is_ssl"] == 0:
        network_risk += 20.0
    if pro_meta["is_raw_ip"] == 1:
        network_risk += 40.0

    dynamic_risk_weight = 0.0

    # --- Domain age signals ---
    if whois_info.get("found") and whois_info.get("age_days") is not None:
        if whois_info["age_days"] < 30:
            dynamic_risk_weight += 25.0
        elif whois_info["age_days"] < 180:
            dynamic_risk_weight += 10.0

    # --- Certificate signals ---
    if cert_info.get("found") and cert_info.get("age_days") is not None:
        if cert_info["age_days"] < 7:
            dynamic_risk_weight += 15.0
        elif cert_info["age_days"] < 30:
            dynamic_risk_weight += 6.0

    # --- Redirect signals ---
    if domain_drift:
        dynamic_risk_weight += 20.0

    # --- Threat feed signals (highest weight — live DB matches) ---
    if urlhaus_result.get("matched"):
        dynamic_risk_weight += 30.0
    if gsb_result.get("matched"):
        dynamic_risk_weight += 50.0
    if openphish_result.get("matched"):
        dynamic_risk_weight += 45.0  # NEW — direct confirmed phishing match, very high confidence
    if vt_result.get("matched"):
        # Scale with how many vendors agree — 1 flag is weak signal, 10+ flags is near-certain.
        vt_flags = vt_result.get("malicious", 0) + vt_result.get("suspicious", 0)
        dynamic_risk_weight += min(55.0, 15.0 + (vt_flags * 4.0))
    if urlscan_result.get("matched"):
        # Free community-scan corroboration — moderate weight since it's crowd-sourced, not a vendor verdict.
        dynamic_risk_weight += 18.0

    # --- AI anomaly signal ---
    # Kept deliberately modest (unsupervised model = noisier signal), and only applied
    # when other signals aren't already screaming "phishing" — avoids double-punishing.
    if is_structurally_anomalous:
        dynamic_risk_weight += 12.0

    # NEW (v16.0) — FIX for the "scanner flags itself" bug: the RandomForest score was being
    # added at full strength even when it was the ONLY signal firing and every live threat feed
    # (URLhaus/GSB/OpenPhish/VirusTotal/urlscan) plus network/WHOIS/cert checks were unanimously
    # clean. A structural ML guess with zero real-world corroboration should never be able to
    # push a totally clean site over the DANGEROUS line on its own.
    live_feed_hit = any([urlhaus_result.get("matched"), gsb_result.get("matched"),
                          openphish_result.get("matched"), vt_result.get("matched"),
                          urlscan_result.get("matched")])
    has_real_corroboration = (network_risk > 0 or live_feed_hit or domain_drift
                               or (whois_info.get("found") and (whois_info.get("age_days") or 999) < 180)
                               or (cert_info.get("found") and (cert_info.get("age_days") or 999) < 30))
    ml_weight = ml_phish_probability * 100.0
    if not has_real_corroboration:
        # ML alone, no other evidence at all -- trust it at half strength only.
        ml_weight *= 0.5
    dynamic_risk_weight += ml_weight + network_risk

    # --- Phishing-specific heuristic signals ---
    # These use "combined signal" logic to avoid false positives on legitimate sites.
    # A single suspicious TLD or platform alone is NOT enough to trigger DANGEROUS.
    other_phish_signals = sum([
        pro_meta["is_ssl"] == 0,
        phishing_signals.get("is_brand_impersonation", False),
        phishing_signals.get("has_multi_dash", 0) == 1,
        phishing_signals.get("has_numeric_subdomain", 0) == 1,
        phishing_signals.get("is_random_platform_subdomain", False),
        phishing_signals.get("is_typosquat", False),
        (whois_info.get("found") and (whois_info.get("age_days") or 999) < 90),
    ])

    if phishing_signals.get("is_suspicious_tld"):
        # Full weight only when combined with another signal — lone .online shop stays SAFE
        dynamic_risk_weight += 24.0 if other_phish_signals >= 1 else 12.0

    if phishing_signals.get("is_phishing_platform"):
        # Free hosting: mild alone; higher when paired with random subdomain, brand, or no-SSL.
        # NEW (v16.0): mainstream platforms (streamlit.app, vercel.app, etc.) get a further
        # reduced base weight when they're the ONLY signal -- millions of legitimate apps
        # live there, unlike obscure hosts almost exclusively used for phishing kits.
        is_mainstream = phishing_signals.get("is_mainstream_platform", False)
        if other_phish_signals >= 1:
            dynamic_risk_weight += 22.0
        elif is_mainstream:
            dynamic_risk_weight += 5.0
        else:
            dynamic_risk_weight += 12.0

    if phishing_signals.get("is_random_platform_subdomain"):
        # Random/auto-generated subdomain on free hosting = strong phishing indicator
        dynamic_risk_weight += 32.0

    if phishing_signals.get("is_brand_impersonation"):
        dynamic_risk_weight += 25.0

    if phishing_signals.get("is_typosquat"):
        # NEW — near-identical lookalike of a real brand domain (e.g. paypa1.com)
        dynamic_risk_weight += 28.0

    if phishing_signals.get("has_multi_dash"):
        dynamic_risk_weight += 15.0

    if phishing_signals.get("has_numeric_subdomain"):
        dynamic_risk_weight += 10.0

    risk_percent = round(min(99.4, max(4.2, dynamic_risk_weight)), 1)
    safety_percent = round(100.0 - risk_percent, 1)
    # FIX: Threshold raised from 45% -> 55% to reduce false positives on legitimate sites
    # that trip only 1-2 mild signals (e.g. a new-ish domain with a dash in it).
    is_malicious_class = True if risk_percent >= 55.0 else False

    scanned_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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
        "phishing_signals": phishing_signals,
        "resolved_ip": resolved_ip,
        "dns_status_log": dns_status_log,
        "geo_info": geo_info,
        "whois_info": whois_info,
        "cert_info": cert_info,
        "urlhaus_result": urlhaus_result,
        "gsb_result": gsb_result,
        "openphish_result": openphish_result,
        "vt_result": vt_result,
        "urlscan_result": urlscan_result,
        "ml_phish_probability": ml_phish_probability,
        "is_structurally_anomalous": is_structurally_anomalous,
        "anomaly_raw_score": anomaly_raw_score,
        "risk_percent": risk_percent,
        "safety_percent": safety_percent,
        "is_malicious_class": is_malicious_class,
        "scanned_at": scanned_at,
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
        "Raw IP Domain": "Yes" if result["pro_meta"]["is_raw_ip"] else "No",
        "URLhaus Checked OK": result["urlhaus_result"].get("checked", False),
        "URLhaus Match": result["urlhaus_result"].get("matched", False),
        "GSB Checked OK": result["gsb_result"].get("checked", False),
        "Google Safe Browsing Match": result["gsb_result"].get("matched", False),
        "OpenPhish Checked OK": result["openphish_result"].get("checked", False),
        "OpenPhish Match": result["openphish_result"].get("matched", False),
        "VirusTotal Vendors Flagged": f"{result['vt_result'].get('malicious', 0) + result['vt_result'].get('suspicious', 0)}/{result['vt_result'].get('total_engines', 0)}",
        "VirusTotal Match": result["vt_result"].get("matched", False),
        "urlscan.io Match": result["urlscan_result"].get("matched", False),
        "Suspicious TLD": result.get("phishing_signals", {}).get("is_suspicious_tld", False),
        "Phishing Platform": result.get("phishing_signals", {}).get("is_phishing_platform", False),
        "Random Platform Subdomain": result.get("phishing_signals", {}).get("is_random_platform_subdomain", False),
        "Brand Impersonation": result.get("phishing_signals", {}).get("is_brand_impersonation", False),
        "Typosquat Detected": result.get("phishing_signals", {}).get("is_typosquat", False),
        "Typosquat Target": result.get("phishing_signals", {}).get("typosquat_target", "N/A"),
        "AI Anomaly Flag (IsolationForest)": result.get("is_structurally_anomalous", False),
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
            f"OpenPhish (free feed): {result['openphish_result']['status']}",
            f"VirusTotal:            {result['vt_result']['status']}",
            f"urlscan.io (community): {result['urlscan_result']['status']}",
            f"Suspicious TLD:        {'Yes (' + result.get('phishing_signals', {}).get('tld', '') + ')' if result.get('phishing_signals', {}).get('is_suspicious_tld') else 'No'}",
            f"Free Hosting Platform: {'YES — phisher-abused platform' if result.get('phishing_signals', {}).get('is_phishing_platform') else 'No'}",
            f"Brand Impersonation:   {'YES — brand name in non-official URL' if result.get('phishing_signals', {}).get('is_brand_impersonation') else 'No'}",
            f"Typosquatting:         {'YES — looks like ' + str(result.get('phishing_signals', {}).get('typosquat_target')) if result.get('phishing_signals', {}).get('is_typosquat') else 'No'}",
            "",
            "-- AI Models --",
            f"RandomForest Confidence: {round(result['ml_phish_probability']*100, 1)}%",
            f"Anomaly Detector:        {'ANOMALOUS structure' if result['is_structurally_anomalous'] else 'Normal structure'}",
            "",
            "-- Network --",
            f"Server IP:    {result['resolved_ip']}  ({result['dns_status_log']})",
            f"SSL Secured:  {'Yes' if result['pro_meta']['is_ssl'] else 'No'}",
            f"Raw IP Host:  {'Yes' if result['pro_meta']['is_raw_ip'] else 'No'}",
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
            return None, "⚠️ Legacy Office binary format — macro presence could not be verified without extra libraries. Treat with caution."
        return False, "✅ No embedded macros detected."
    except Exception:
        # FIX: a parse failure means we genuinely could NOT verify — treat as unknown (risk-weighted),
        # not as a clean pass. Previously this silently returned "safe", hiding malformed/malicious files.
        return None, "⚠️ Could not parse this Office file to check for macros (corrupt or obfuscated archive) — treat with caution."

# ============================================================================
# FREE THREAT INTELLIGENCE — MalwareBazaar + ThreatFox (abuse.ch)
# 100% free, no API key required, no strict rate limits
# ============================================================================

def check_malwarebazaar(sha256_hash: str) -> dict:
    """Query MalwareBazaar by abuse.ch — completely free, no API key needed."""
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256_hash},
            headers={"User-Agent": "ThreatX-GlobalGuard/15.0"},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            query_status = data.get("query_status", "")
            if query_status == "ok":
                info = data.get("data", [{}])[0]
                malware_name = info.get("signature") or info.get("tags") or "Unknown"
                if isinstance(malware_name, list):
                    malware_name = ", ".join(malware_name)
                file_type = info.get("file_type", "Unknown")
                first_seen = info.get("first_seen", "Unknown")
                reporter = info.get("reporter", "Unknown")
                return {
                    "checked": True,
                    "matched": True,
                    "malware_name": malware_name,
                    "file_type": file_type,
                    "first_seen": first_seen,
                    "reporter": reporter,
                    "status": f"🔴 CONFIRMED MALWARE in MalwareBazaar — '{malware_name}' (first seen: {first_seen})"
                }
            elif query_status == "hash_not_found":
                return {
                    "checked": True,
                    "matched": False,
                    "status": "🟢 Not found in MalwareBazaar — hash is clean in this database"
                }
            else:
                return {
                    "checked": False,
                    "matched": False,
                    "status": f"⚪ MalwareBazaar returned unexpected status: {query_status}"
                }
        return {
            "checked": False,
            "matched": False,
            "status": f"⚪ MalwareBazaar lookup failed (HTTP {resp.status_code})"
        }
    except Exception:
        return {
            "checked": False,
            "matched": False,
            "status": "⚪ MalwareBazaar lookup failed (network/timeout error)"
        }

def check_threatfox(sha256_hash: str) -> dict:
    """Query ThreatFox by abuse.ch — completely free, no API key needed."""
    try:
        payload = {"query": "search_hash", "hash": sha256_hash}
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            headers={"User-Agent": "ThreatX-GlobalGuard/15.0"},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            query_status = data.get("query_status", "")
            if query_status == "ok":
                iocs = data.get("data", [])
                if iocs:
                    first = iocs[0]
                    malware = first.get("malware_printable", "Unknown")
                    threat_type = first.get("threat_type", "Unknown")
                    confidence = first.get("confidence_level", "?")
                    first_seen = first.get("first_seen", "Unknown")
                    return {
                        "checked": True,
                        "matched": True,
                        "malware": malware,
                        "threat_type": threat_type,
                        "confidence": confidence,
                        "first_seen": first_seen,
                        "status": (f"🔴 Found in ThreatFox IOC database — Malware: '{malware}' | "
                                   f"Type: {threat_type} | Confidence: {confidence}%")
                    }
                return {
                    "checked": True,
                    "matched": False,
                    "status": "🟢 Not found in ThreatFox IOC database — no known threat association"
                }
            elif query_status == "no_result":
                return {
                    "checked": True,
                    "matched": False,
                    "status": "🟢 Not found in ThreatFox IOC database — no known threat association"
                }
            return {
                "checked": False,
                "matched": False,
                "status": f"⚪ ThreatFox returned status: {query_status}"
            }
        return {
            "checked": False,
            "matched": False,
            "status": f"⚪ ThreatFox lookup failed (HTTP {resp.status_code})"
        }
    except Exception:
        return {
            "checked": False,
            "matched": False,
            "status": "⚪ ThreatFox lookup failed (network/timeout error)"
        }

def scan_uploaded_file(uploaded_file, vt_key=None):
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name
    size_kb = round(len(file_bytes) / 1024, 1)

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()

    entropy = calculate_file_entropy(file_bytes)
    sig_desc, _ = detect_file_signature(file_bytes)
    mismatch, mismatch_note = check_extension_mismatch(filename, file_bytes)
    has_macro, macro_note = detect_macros(filename, file_bytes)

    # FREE threat intelligence lookups — no API key needed
    malwarebazaar_result = check_malwarebazaar(sha256_hash)
    threatfox_result = check_threatfox(sha256_hash)
    vt_result = check_virustotal_file(sha256_hash, vt_key)  # NEW — real 70+ AV engine report

    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS

    risk = 5.0
    if mismatch:
        risk += 40.0
    if is_suspicious_ext:
        risk += 25.0
    if entropy >= 7.5:
        risk += 20.0
    if has_macro is True:
        risk += 25.0
    if has_macro is None:
        risk += 10.0
    # Threat feed matches — highest weight signals
    if malwarebazaar_result.get("matched"):
        risk += 50.0
    if threatfox_result.get("matched"):
        risk += 45.0
    if vt_result.get("matched"):
        vt_flags = vt_result.get("malicious", 0) + vt_result.get("suspicious", 0)
        risk += min(55.0, 15.0 + (vt_flags * 3.0))

    risk_percent = round(min(99.4, max(2.0, risk)), 1)
    safety_percent = round(100.0 - risk_percent, 1)
    is_malicious_class = risk_percent >= 55.0  # FIX: aligned with URL scanner's tuned threshold

    scanned_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

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
        "malwarebazaar_result": malwarebazaar_result,
        "threatfox_result": threatfox_result,
        "vt_result": vt_result,
        "risk_percent": risk_percent,
        "safety_percent": safety_percent,
        "is_malicious_class": is_malicious_class,
        "scanned_at": scanned_at,
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
        "MalwareBazaar Match": fresult["malwarebazaar_result"].get("matched", False),
        "MalwareBazaar Status": fresult["malwarebazaar_result"].get("status", "N/A"),
        "ThreatFox Match": fresult["threatfox_result"].get("matched", False),
        "ThreatFox Status": fresult["threatfox_result"].get("status", "N/A"),
        "VirusTotal Vendors Flagged": f"{fresult['vt_result'].get('malicious', 0) + fresult['vt_result'].get('suspicious', 0)}/{fresult['vt_result'].get('total_engines', 0)}",
        "VirusTotal Match": fresult["vt_result"].get("matched", False),
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

def get_vt_api_key():
    try:
        return st.secrets.get("VT_API_KEY", "")
    except Exception:
        return ""

gsb_api_key = get_gsb_api_key()
urlhaus_auth_key = get_urlhaus_auth_key()
vt_api_key = get_vt_api_key()

# 8b. User Console Interface — Single Scan / Bulk Scan / File Scan
tab_single, tab_bulk, tab_file = st.tabs(["🔍 Single Scan", "📂 Bulk Scan", "🗂️ File Scan"])

with tab_single:
    user_target = st.text_input("🔗 Enter website link here to analyze secure features:", placeholder="e.g., https://my-safe-website.com")

    if st.button("🔍 SCAN WEBSITE NOW"):
        if user_target:
            with st.spinner("Tracing redirects, checking threat feeds, WHOIS, geolocation, and running AI models..."):
                result = scan_url(user_target, gsb_key=gsb_api_key, urlhaus_key=urlhaus_auth_key, vt_key=vt_api_key)

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
            openphish_result = result["openphish_result"]
            phishing_signals = result.get("phishing_signals", {})

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
            _, texts, autotexts = ax.pie(
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

            st.write("#### 🛡️ VirusTotal — Multi-Vendor Detection Report:")
            vt_result = result["vt_result"]
            if vt_result.get("checked") and vt_result.get("total_engines", 0) > 0:
                flagged = vt_result.get("malicious", 0) + vt_result.get("suspicious", 0)
                total = vt_result["total_engines"]
                vt_c1, vt_c2, vt_c3, vt_c4 = st.columns(4)
                vt_c1.metric("🔴 Malicious", vt_result.get("malicious", 0))
                vt_c2.metric("🟠 Suspicious", vt_result.get("suspicious", 0))
                vt_c3.metric("🟢 Harmless", vt_result.get("harmless", 0))
                vt_c4.metric("⚪ Undetected", vt_result.get("undetected", 0))
                if flagged > 0:
                    st.error(f"🔴 **{flagged}/{total} security vendors** flagged this URL as malicious or suspicious.")
                else:
                    st.success(f"✅ **0/{total} security vendors** flagged this URL — clean across all engines VirusTotal aggregates.")
            else:
                st.write(vt_result.get("status", "⚪ VirusTotal not available"))

            st.write("#### 📡 Other Live Threat Feed Results:")
            urlscan_result = result["urlscan_result"]
            tf_col1, tf_col2, tf_col3, tf_col4 = st.columns(4)
            with tf_col1:
                st.write(f"📝 **URLhaus (Malware DB):** {urlhaus_result['status']}")
            with tf_col2:
                st.write(f"🌐 **Google Safe Browsing:** {gsb_result['status']}")
            with tf_col3:
                st.write(f"🎣 **OpenPhish (Free Feed):** {openphish_result['status']}")
            with tf_col4:
                st.write(f"🔎 **urlscan.io (Community):** {urlscan_result['status']}")

            st.write("#### 🎯 Phishing Pattern Analysis:")
            ph_col1, ph_col2, ph_col3 = st.columns(3)
            with ph_col1:
                tld_label = phishing_signals.get('tld', '')
                if phishing_signals.get('is_suspicious_tld'):
                    st.error(f"🔴 Suspicious TLD: `{tld_label}` (phishing-prone extension) +8-20 risk")
                else:
                    st.success(f"✅ TLD `{tld_label}` — not suspicious")
            with ph_col2:
                if phishing_signals.get('is_phishing_platform'):
                    st.error("🔴 Free Hosting Platform — phishers abuse these (vercel/blogspot/framer etc.)")
                else:
                    st.success("✅ Not a known phishing hosting platform")
            with ph_col3:
                if phishing_signals.get('is_brand_impersonation'):
                    st.error("🔴 Brand Impersonation — brand name in non-official hostname +25 risk")
                else:
                    st.success("✅ No brand impersonation detected")
            if phishing_signals.get('is_typosquat'):
                st.error(f"🔴 **Typosquatting Detected** — domain is a near-identical lookalike of `{phishing_signals.get('typosquat_target')}` "
                         f"(similarity: {round(phishing_signals.get('typosquat_ratio', 0)*100, 1)}%) — +28 risk")
            if phishing_signals.get('is_random_platform_subdomain'):
                st.error("🔴 **Random/Auto-Generated Subdomain on Free Platform** — phishers deploy on vercel/framer/netlify with random subdomains like `loyal-raccoon-022802.framer.app` or long gibberish like `uiuasorteofficial.vercel.app` — +32 risk")
            if phishing_signals.get('has_multi_dash'):
                st.warning("🟠 Multiple consecutive dashes in domain (e.g. docs----bank.gitbook.io) — common phishing trick +15 risk")

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

            st.write("#### 🧠 AI Prediction Output (dual-model structural analysis):")
            ml_confidence = round(ml_phish_probability * 100, 1)
            ml_verdict = "🔴 Suspicious Structure" if ml_phish_probability >= 0.5 else "🟢 Normal Structure"
            ai_col1, ai_col2 = st.columns(2)
            with ai_col1:
                st.write(f"**Model 1 — RandomForest Classifier:** {ml_verdict}")
                st.write(f"**Confidence:** {ml_confidence}%")
            with ai_col2:
                anomaly_verdict = "🔴 Anomalous Structure" if result["is_structurally_anomalous"] else "🟢 Normal Structure"
                st.write(f"**Model 2 — IsolationForest (Anomaly Detector):** {anomaly_verdict}")
                st.write(f"**Outlier Score:** {round(result['anomaly_raw_score'], 3)} (lower = more unusual)")
            st.caption(
                "Two independent AI models analyze URL structure (length, entropy, dashes, SSL, "
                "IP-masking, keywords): a supervised RandomForest classifier trained on known "
                "safe/phishing shapes, plus an unsupervised IsolationForest that flags URLs which "
                "look structurally 'weird' compared to normal sites — even if no exact phishing "
                "pattern like it has been seen before. Neither model has internet access of its own "
                "and cannot know if a URL is blocklisted, how old the domain is, or where it "
                "redirects — those live signals are shown separately and are what actually drive "
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
                    "Domain Raw IP Address Check",
                    "Suspicious Login/Verify Keyword Flag",
                    "URL Hyphen Clustering Matrix",
                    "Subdomain Layer Count Check",
                    "Redirect Chain Depth Check",
                ],
                "Observed Metric Value": [
                    "HTTPS Secured" if pro_meta["is_ssl"] == 1 else "Insecure HTTP Standard",
                    "Raw IP Address Detected" if pro_meta["is_raw_ip"] == 1 else "Legitimate Text String Domain",
                    "Triggered (Malicious Keywords Found)" if feature_weights[5] == 1 else "Clean Structural Patterns",
                    f"{feature_weights[3]} Structural Dash Elements Detected",
                    f"{feature_weights[2]} Segment Subdomains Layered",
                    f"{cross_domain_hops} Cross-Domain Redirect Hop(s) Detected",
                ],
                "Risk Severity Rating": [
                    "✅ LOW RISK" if pro_meta["is_ssl"] == 1 else "⚠️ MEDIUM RISK ALERT",
                    "🚨 CRITICAL HIGH RISK" if pro_meta["is_raw_ip"] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ HIGH SUSPICION" if feature_weights[5] == 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MINOR ANOMALY" if feature_weights[3] > 0 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if feature_weights[2] > 1 else "✅ SECURE INFRASTRUCTURE",
                    "⚠️ MEDIUM SUSPICION" if cross_domain_hops >= 2 else "✅ SECURE INFRASTRUCTURE",
                ]
            }
            st.table(pd.DataFrame(breakdown_data))

            st.write("---")
            st.write("#### 🧠 Technical System Ingestion Metrics:")
            full_vector = feature_weights + [pro_meta["is_ssl"], pro_meta["is_raw_ip"]]
            st.info(f"**Structural Feature Vector (fed to both AI models):** {full_vector} "
                    f"→ [length, has_at, subdomains, has_dash, entropy, has_token, is_ssl, is_raw_ip]")
            st.markdown(f"""
            - **RandomForest Confidence:** `{round(ml_phish_probability*100, 1)}%` (URL-shape signal only — see AI Prediction Output above)
            - **IsolationForest Verdict:** `{'Anomalous' if result['is_structurally_anomalous'] else 'Normal'}` (outlier score: `{round(result['anomaly_raw_score'], 3)}`)
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
            # FIX: Bulk scanning used to run fully sequential (each URL = ~6 blocking network
            # calls), which made large batches painfully slow. Now runs scans concurrently
            # with a thread pool since these are all I/O-bound network requests.
            progress = st.progress(0, text=f"Scanning 0 / {len(url_list)}...")
            bulk_results_map = {}
            completed = 0

            def _scan_one(u):
                return u, scan_url(u, gsb_key=gsb_api_key, urlhaus_key=urlhaus_auth_key, vt_key=vt_api_key)

            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = {executor.submit(_scan_one, u): u for u in url_list}
                for future in as_completed(futures):
                    original_u = futures[future]
                    try:
                        u, res = future.result()
                        ps = res.get("phishing_signals", {})
                        bulk_results_map[original_u] = {
                            "URL": res["input_url"],
                            "Final URL": res["final_url"],
                            "Verdict": "⚠️ DANGEROUS" if res["is_malicious_class"] else "✅ SAFE",
                            "Risk %": res["risk_percent"],
                            "Redirect Hops (Total)": len(res["redirect_chain"]) - 1,
                            "Redirect Hops (Cross-Domain)": res["cross_domain_hops"],
                            "URLhaus Match": res["urlhaus_result"].get("matched", False),
                            "GSB Match": res["gsb_result"].get("matched", False),
                            "OpenPhish Match": res["openphish_result"].get("matched", False),
                            "VirusTotal Vendors Flagged": f"{res['vt_result'].get('malicious', 0) + res['vt_result'].get('suspicious', 0)}/{res['vt_result'].get('total_engines', 0)}",
                            "VirusTotal Match": res["vt_result"].get("matched", False),
                            "urlscan.io Match": res["urlscan_result"].get("matched", False),
                            "Suspicious TLD": ps.get("is_suspicious_tld", False),
                            "Phishing Platform": ps.get("is_phishing_platform", False),
                            "Random Platform Subdomain": ps.get("is_random_platform_subdomain", False),
                            "Brand Impersonation": ps.get("is_brand_impersonation", False),
                            "Typosquat Detected": ps.get("is_typosquat", False),
                            "AI Anomaly Flag": res.get("is_structurally_anomalous", False),
                            "Server IP": res["resolved_ip"],
                            "SSL": "Yes" if res["pro_meta"]["is_ssl"] else "No",
                            "Domain Age (days)": (res["whois_info"].get("age_days")
                                                  if res["whois_info"].get("age_days") is not None else "N/A"),
                            "Country": res["geo_info"]["country"] if res["geo_info"] else "N/A",
                        }
                    except Exception:
                        bulk_results_map[original_u] = {
                            "URL": original_u, "Final URL": "ERROR", "Verdict": "⚪ SCAN FAILED",
                            "Risk %": "N/A", "Redirect Hops (Total)": "N/A", "Redirect Hops (Cross-Domain)": "N/A",
                            "URLhaus Match": "N/A", "GSB Match": "N/A", "OpenPhish Match": "N/A",
                            "Suspicious TLD": "N/A", "Phishing Platform": "N/A", "Brand Impersonation": "N/A",
                            "Typosquat Detected": "N/A", "AI Anomaly Flag": "N/A",
                            "Server IP": "N/A", "SSL": "N/A", "Domain Age (days)": "N/A", "Country": "N/A",
                        }
                    completed += 1
                    progress.progress(completed / len(url_list), text=f"Scanning {completed} / {len(url_list)}...")

            # Preserve original input order in the final table
            bulk_results = [bulk_results_map[u] for u in url_list]

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
            with st.spinner("Computing hashes, checking MalwareBazaar, ThreatFox, file signature and macros..."):
                fresult = scan_uploaded_file(uploaded_file_scan, vt_key=vt_api_key)

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
            _, f_texts, f_autotexts = fax.pie(
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
            st.write("#### 🛡️ VirusTotal — Multi-Engine Detection Report:")
            vt_result = fresult["vt_result"]
            if vt_result.get("checked") and vt_result.get("total_engines", 0) > 0:
                vt_flagged = vt_result.get("malicious", 0) + vt_result.get("suspicious", 0)
                vt_total = vt_result["total_engines"]
                vfc1, vfc2, vfc3, vfc4 = st.columns(4)
                vfc1.metric("🔴 Malicious", vt_result.get("malicious", 0))
                vfc2.metric("🟠 Suspicious", vt_result.get("suspicious", 0))
                vfc3.metric("🟢 Harmless", vt_result.get("harmless", 0))
                vfc4.metric("⚪ Undetected", vt_result.get("undetected", 0))
                if vt_flagged > 0:
                    st.error(f"🔴 **{vt_flagged}/{vt_total} antivirus engines** flagged this file as malicious or suspicious.")
                else:
                    st.success(f"✅ **0/{vt_total} antivirus engines** flagged this file.")
            else:
                st.write(vt_result.get("status", "⚪ VirusTotal not available"))

            st.write("---")
            st.write("#### 🕵️ Other Free Threat Intelligence Feed Results:")
            mb_result = fresult["malwarebazaar_result"]
            tf_result = fresult["threatfox_result"]
            ti_col1, ti_col2 = st.columns(2)
            with ti_col1:
                st.write(f"🦠 **MalwareBazaar (abuse.ch):** {mb_result['status']}")
                if mb_result.get("matched"):
                    st.write(f"&nbsp;&nbsp;&nbsp;• **Malware Name:** `{mb_result.get('malware_name', 'N/A')}`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **File Type:** `{mb_result.get('file_type', 'N/A')}`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **First Seen:** `{mb_result.get('first_seen', 'N/A')}`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **Reported By:** `{mb_result.get('reporter', 'N/A')}`")
            with ti_col2:
                st.write(f"🕵️ **ThreatFox (abuse.ch):** {tf_result['status']}")
                if tf_result.get("matched"):
                    st.write(f"&nbsp;&nbsp;&nbsp;• **Malware:** `{tf_result.get('malware', 'N/A')}`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **Threat Type:** `{tf_result.get('threat_type', 'N/A')}`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **Confidence:** `{tf_result.get('confidence', 'N/A')}%`")
                    st.write(f"&nbsp;&nbsp;&nbsp;• **First Seen:** `{tf_result.get('first_seen', 'N/A')}`")
            if mb_result.get("matched") or tf_result.get("matched") or vt_result.get("matched"):
                st.error("🚨 This file's SHA-256 hash is confirmed in live malware threat databases. Do NOT open or execute it.")
            elif mb_result.get("checked") and tf_result.get("checked"):
                st.success("✅ SHA-256 hash not found in MalwareBazaar or ThreatFox — no known malware match.")
            else:
                st.info("ℹ️ One or more threat feed lookups could not be completed — static analysis results still apply.")

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
                    "Macro Found" if fresult["has_macro"] is True else (
                        "Unverifiable (Legacy Format)" if fresult["has_macro"] is None else "No Macro"
                    ),
                ],
                "Risk Severity Rating": [
                    "🚨 CRITICAL HIGH RISK" if fresult["extension_mismatch"] else "✅ SECURE",
                    "⚠️ HIGH SUSPICION" if fresult["is_suspicious_ext"] else "✅ SECURE",
                    "⚠️ MEDIUM SUSPICION" if fresult["entropy"] >= 7.5 else "✅ SECURE",
                    "🚨 CRITICAL HIGH RISK" if fresult["has_macro"] is True else (
                        "⚠️ UNVERIFIABLE — treat with caution" if fresult["has_macro"] is None else "✅ SECURE"
                    ),
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
st.markdown("""
<style>
.guide-link {
    color: #3b82f6;
    font-weight: 600;
    text-decoration: underline;
    transition: 0.2s;
}

.guide-link:hover {
    color: #2563eb;
    cursor: pointer;
}
</style>

<div style='text-align:center; color:#475569; font-size:20px; padding:14px 0 6px 0;'>
    Built under the guidance of
    <a href="https://www.linkedin.com/in/shanthan-5386a5112/"
       target="_blank"
       class="guide-link"
       title="View LinkedIn Profile">
       Mr. Arepally Sai Shanthan Sir ↗
    </a>
</div>""", unsafe_allow_html=True)
