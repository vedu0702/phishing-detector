import streamlit as st
import pandas as pd
import math
import socket
import requests
import re
import io
import datetime
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import plotly.graph_objects as go

st.set_page_config(page_title="🛡 THREAT-X AI", page_icon="🛡️", layout="wide")

custom_css = """
:root{
  --bg1:#0F172A;
  --bg2:#111827;
  --bg3:#1E293B;
  --accent1:#00F5FF;
  --accent2:#00E676;
  --accent3:#7C3AED;
  --glass:rgba(255,255,255,0.08);
  --text:#E5EEF8;
}

.stApp{
  background:
    radial-gradient(900px 400px at 10% 20%, rgba(124,58,237,0.16), transparent 35%),
    radial-gradient(700px 300px at 85% 15%, rgba(0,245,255,0.10), transparent 30%),
    radial-gradient(700px 300px at 70% 85%, rgba(0,230,118,0.10), transparent 30%),
    linear-gradient(120deg, var(--bg1), var(--bg2) 45%, var(--bg3));
  background-size: 200% 200%;
  animation: bgShift 16s ease infinite;
  color: var(--text);
}
@keyframes bgShift{
  0%{background-position:0% 0%}
  50%{background-position:100% 100%}
  100%{background-position:0% 0%}
}
header, footer {visibility:hidden;}
#MainMenu {visibility:hidden;}

.navbar{
  display:flex; justify-content:space-between; align-items:center;
  padding:12px 18px; margin-top:4px; margin-bottom:18px;
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.06);
  border-radius:16px;
  backdrop-filter: blur(15px);
}
.brand{
  font-size:20px; font-weight:800; color:white; letter-spacing:0.5px;
}
.brand span{color:var(--accent1)}
.navlinks{
  color:rgba(255,255,255,0.78);
  font-size:14px;
}
.hero{
  padding:20px 22px;
  border-radius:20px;
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.06);
  backdrop-filter: blur(15px);
  box-shadow: 0 10px 40px rgba(0,0,0,0.24);
  margin-bottom:16px;
}
.hero-title{
  font-size:34px;
  font-weight:900;
  line-height:1.1;
  color:#fff;
}
.hero-sub{
  margin-top:8px;
  color:rgba(255,255,255,0.72);
  font-size:15px;
}

.glass-card{
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.10);
  backdrop-filter: blur(15px);
  border-radius:16px;
  padding:16px;
  box-shadow: 0 10px 32px rgba(0,0,0,0.22);
  margin-bottom:14px;
}

.search-box{
  display:flex;
  gap:10px;
  align-items:center;
  padding:8px;
  border-radius:16px;
  border:1px solid rgba(255,255,255,0.10);
  background:rgba(255,255,255,0.04);
  box-shadow: 0 0 0 1px rgba(0,245,255,0.04), 0 0 30px rgba(0,245,255,0.07);
}
.search-icon{
  padding-left:8px;
  font-size:18px;
  color:var(--accent1);
}
div[data-baseweb="input"] > div{
  border-radius:14px !important;
  background:rgba(255,255,255,0.02) !important;
}
div[data-baseweb="input"] input{
  color:white !important;
  font-size:16px !important;
}
button[kind="primary"]{
  background:linear-gradient(90deg, var(--accent1), var(--accent2)) !important;
  color:#06131A !important;
  border:none !important;
  border-radius:14px !important;
  font-weight:800 !important;
  box-shadow: 0 8px 30px rgba(0,245,255,0.18) !important;
  height:48px !important;
}
button[kind="primary"]:hover{
  transform: translateY(-1px);
}

.status-safe{
  border:1px solid rgba(0,230,118,0.25);
  box-shadow: 0 0 30px rgba(0,230,118,0.18), 0 0 60px rgba(0,230,118,0.08);
}
.status-danger{
  border:1px solid rgba(255,80,80,0.25);
  box-shadow: 0 0 30px rgba(255,80,80,0.18), 0 0 60px rgba(255,80,80,0.08);
}
.status-title{
  font-size:24px;
  font-weight:900;
  margin-bottom:10px;
}
.status-grid{
  display:grid;
  grid-template-columns: repeat(3, 1fr);
  gap:12px;
}
.status-item{
  padding:12px;
  border-radius:14px;
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(255,255,255,0.08);
}
.status-label{font-size:13px;color:rgba(255,255,255,0.65)}
.status-value{font-size:22px;font-weight:900;color:#fff;margin-top:4px}

.section-title{
  font-size:18px;
  font-weight:800;
  margin:6px 0 12px 0;
  color:#fff;
}
.mono{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  white-space: pre-wrap;
  color:#D9E7F5;
}
.footer{
  margin-top:18px;
  padding:14px 0 6px 0;
  color:rgba(255,255,255,0.72);
  font-size:13px;
  text-align:center;
}
.timeline{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  line-height:1.6;
  color:#E8F4FF;
}
.small-note{
  color:rgba(255,255,255,0.68);
  font-size:13px;
}
"""

st.markdown(f"<style>{custom_css}</style>", unsafe_allow_html=True)

st.markdown("""
<div class="navbar">
  <div class="brand">🛡 <span>THREAT-X</span></div>
  <div class="navlinks">Home &nbsp;&nbsp; Scanner &nbsp;&nbsp; Bulk Scan &nbsp;&nbsp; About &nbsp;&nbsp; GitHub</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="hero-title">🛡️ THREAT-X AI<br>Enterprise Phishing Detection Platform</div>
  <div class="hero-sub">Premium website authenticity scanner with ML scoring, WHOIS, DNS, geolocation, and redirect tracing.</div>
</div>
""", unsafe_allow_html=True)

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
            age_status = f"🔴 Very new domain — registered {age_days} days ago"
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
    except Exception:
        return {"found": False, "error": "WHOIS lookup failed"}

def trace_redirect_chain(url, max_hops=10):
    chain = [url]
    try:
        resp = requests.get(url, timeout=6.0, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}, stream=True)
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
              'goog1e', 'faceb00k', 'netfliix', 'paypal', 'sbi', 'amazon', 'auth', 'portal']
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
    confidence = round(100.0 - min(99.0, risk_percent * 0.55), 1)
    category = "Trusted" if not is_malicious_class else "Suspicious"
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
        "confidence": confidence,
        "category": category,
        "is_malicious_class": is_malicious_class,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

def build_single_scan_csv(result):
    row = {
        "Scanned URL": result["input_url"],
        "Final URL": result["final_url"],
        "Redirect Hops": len(result["redirect_chain"]) - 1,
        "Verdict": "DANGEROUS" if result["is_malicious_class"] else "SAFE",
        "Risk %": result["risk_percent"],
        "Safety %": result["safety_percent"],
        "Confidence %": result["confidence"],
        "Category": result["category"],
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
        fig.patch.set_facecolor("white")
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
            f"Confidence:   {result['confidence']}%",
            f"Category:     {result['category']}",
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
            lines.append(f"Country: {g['country']}   City: {g['city']}   ISP: {g['isp']}")
        else:
            lines.append("Geolocation unavailable.")
        if len(result["redirect_chain"]) > 1:
            lines.append("")
            lines.append("-- Redirect Chain --")
            for i, hop in enumerate(result["redirect_chain"]):
                lines.append(f"  {i+1}. {hop}")
        ax.text(0.02, 0.98, "\n".join(lines), va="top", ha="left", fontsize=9, family="monospace", transform=ax.transAxes, wrap=True)
        pdf.savefig(fig)
        plt.close(fig)
    return buf.getvalue()

def gauge_fig(value, title):
    color = "#00E676" if value < 35 else "#FACC15" if value < 70 else "#FF4D4D"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        number={"suffix": "%", "font": {"size": 28, "color": "white"}},
        title={"text": f"<b>{title}</b>", "font": {"size": 20, "color": "white"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "white", "visible": False},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(255,255,255,0.03)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 35], "color": "rgba(0,230,118,0.12)"},
                {"range": [35, 70], "color": "rgba(250,204,21,0.12)"},
                {"range": [70, 100], "color": "rgba(255,77,77,0.12)"},
            ],
        },
        domain={"x": [0, 1], "y": [0, 1]},
    ))
    fig.add_annotation(x=0.5, y=0.15, text=f"<b>{value}%</b>", showarrow=False, font=dict(size=20, color="white"), xref="paper", yref="paper")
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=40, b=10, l=10, r=10),
        height=260,
    )
    return fig

def status_html(result):
    safe = not result["is_malicious_class"]
    klass = "status-safe" if safe else "status-danger"
    title = "✅ SAFE WEBSITE" if safe else "🚨 DANGEROUS WEBSITE"
    return f"""
    <div class="glass-card {klass}">
      <div class="status-title">{title}</div>
      <div class="status-grid">
        <div class="status-item">
          <div class="status-label">Risk Score</div>
          <div class="status-value">{result["risk_percent"]}%</div>
        </div>
        <div class="status-item">
          <div class="status-label">Confidence</div>
          <div class="status-value">{result["confidence"]}%</div>
        </div>
        <div class="status-item">
          <div class="status-label">Category</div>
          <div class="status-value">{result["category"]}</div>
        </div>
      </div>
    </div>
    """

def progress_bar_html(label, pct):
    return f"""
    <div class="glass-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <div style="font-weight:800">{label}</div>
        <div style="font-family:monospace">{pct}%</div>
      </div>
      <div style="background:rgba(255,255,255,0.06);border-radius:999px;height:14px;overflow:hidden">
        <div style="width:{pct}%;height:14px;border-radius:999px;background:linear-gradient(90deg,var(--accent3),var(--accent1),var(--accent2));box-shadow:0 0 16px rgba(0,245,255,0.22)"></div>
      </div>
    </div>
    """

left, right = st.columns([1.05, 1.6], gap="large")

with left:
    user_target = st.text_input("🔍 Enter Website URL", placeholder="https://example.com", label_visibility="collapsed")
    scan_btn = st.button("Scan Website", type="primary", use_container_width=True)

    st.markdown("<div class='glass-card'><div class='section-title'>🧭 Live Scan</div><div class='small-note' id='scanlog'>Ready to scan.</div></div>", unsafe_allow_html=True)
    log_ph = st.empty()
    status_ph = st.empty()

with right:
    gauge_ph = st.empty()

if scan_btn and user_target:
    steps = [
        "Scanning DNS...",
        "Checking SSL...",
        "Loading WHOIS...",
        "Running AI...",
    ]
    for s in steps:
        log_ph.markdown(f"<div class='glass-card'><div class='section-title'>🧭 Live Scan</div><div class='mono'>{s}\n{'█' * (len(s) // 2)}</div></div>", unsafe_allow_html=True)
        time.sleep(0.45)

    with st.spinner("Analyzing URL..."):
        result = scan_url(user_target)

    status_ph.markdown(status_html(result), unsafe_allow_html=True)
    gauge_ph.plotly_chart(gauge_fig(result["risk_percent"], "Risk Meter"), use_container_width=True)

    st.markdown(progress_bar_html("Risk Progress", result["risk_percent"]), unsafe_allow_html=True)
    st.markdown(progress_bar_html("AI Confidence", result["confidence"]), unsafe_allow_html=True)

    st.markdown("### 📡 System Integrity Verification", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div class="glass-card">
          <div class="section-title">🌐 DNS</div>
          <div class="mono">Server IP: {result["resolved_ip"]}\nStatus: {result["dns_status_log"]}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(f"""
        <div class="glass-card">
          <div class="section-title">📜 WHOIS</div>
          <div class="mono">Registrar: {result["whois_info"].get("registrar", "N/A")}\nCreated: {result["whois_info"].get("creation_date", "N/A")}\nExpires: {result["whois_info"].get("expiration_date", "N/A")}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="glass-card">
          <div class="section-title">🌎 Geolocation</div>
          <div class="mono">{(
            f"Country: {result['geo_info']['country']}\nCity: {result['geo_info']['city']}\nRegion: {result['geo_info']['region']}\nISP: {result['geo_info']['isp']}"
            if result["geo_info"] else "Geolocation unavailable."
          )}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown(f"""
        <div class="glass-card">
          <div class="section-title">🔀 Redirects</div>
          <div class="timeline">{chr(10).join([f"● {u}" for u in result["redirect_chain"]])}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### 🧠 AI Prediction", unsafe_allow_html=True)
    st.info(f"Extracted Feature Vector: {result['feature_weights']}")
    st.markdown(f"- Random Forest Base Confidence Core: `{round(result['ml_phish_probability']*100, 1)}%`")
    st.markdown(f"- URL Lexical Parameters: Length `{result['feature_weights'][0]}` | Subdomains `{result['feature_weights'][2]}` | Hyphens `{result['feature_weights'][3]}` | Entropy `{result['feature_weights'][4]}`")

    st.markdown("### 📥 Export Report", unsafe_allow_html=True)
    d1, d2 = st.columns(2)
    with d1:
        st.download_button("⬇️ Download PDF Report", data=build_single_scan_pdf(result), file_name=f"threatx_report_{result['host_domain']}.pdf", mime="application/pdf", use_container_width=True)
    with d2:
        st.download_button("⬇️ Download CSV Report", data=build_single_scan_csv(result), file_name=f"threatx_report_{result['host_domain']}.csv", mime="text/csv", use_container_width=True)

    if result["is_malicious_class"]:
        st.error("🛑 ACTION RECOMMENDED: This URL shows suspicious characteristics.")
    else:
        st.success("✔ SECURITY CLEARANCE GRANTED: No phishing behavior detected.")

st.markdown("""
<div class="footer">
Powered by AI · Machine Learning · Random Forest · Python · Streamlit · Made by Vedant Agrawal
</div>
""", unsafe_allow_html=True)
