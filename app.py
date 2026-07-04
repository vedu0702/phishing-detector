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

# WHOIS - Optional, agar install hai toh use karo
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="Threat-X Global Guard Pro",
    page_icon="🛡️",
    layout="centered"
)

# ============================================================
# CUSTOM CSS - SIRF NECESSARY STYLING
# ============================================================
st.markdown("""
    <style>
    .main { background-color: #060814; }
    .stButton>button {
        background-color: #00ffcc;
        color: #060814;
        font-weight: bold;
        width: 100%;
        border-radius: 6px;
        height: 52px;
        font-size: 18px;
        border: none;
    }
    .stButton>button:hover {
        background-color: #00ccaa;
        box-shadow: 0px 0px 25px #00ffcc;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    </style>
""", unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================
st.write("""
<div style='text-align: center; padding-top: 10px;'>
    <span style='font-size: 38px; font-weight: 800; color: #ffffff;'>THREAT</span>
    <span style='font-size: 38px; font-weight: 800; color: #00ffcc;'>-X</span>
    <span style='font-size: 14px; font-weight: bold; color: #475569;'>GLOBAL GUARD PRO v13.0</span>
</div>
<p style='text-align: center; color: #94a3b8; font-size: 15px;'>
    Enter any website address to run automated security scanners.
</p>
""", unsafe_allow_html=True)

st.write("---")

# ============================================================
# ML MODEL - CACHED
# ============================================================
@st.cache_resource
def get_model():
    data = [
        [15,0,0,0,2.4,0,0], [18,0,1,0,2.7,0,0],
        [22,0,2,0,3.1,0,0], [28,0,0,0,2.9,0,0],
        [32,0,1,2,4.2,1,1], [45,0,0,2,4.1,1,1],
        [55,0,1,2,4.3,1,1], [72,1,2,1,4.5,1,1],
        [34,0,1,2,4.2,1,1], [17,0,1,0,4.4,1,1],
        [26,0,2,1,4.1,1,1], [38,0,1,1,4.0,1,1]
    ]
    cols = ['length','has_at','subdomains','has_dash','entropy','has_token','result']
    df = pd.DataFrame(data, columns=cols)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(df[cols[:-1]], df['result'])
    return clf

model = get_model()

# ============================================================
# CORE FUNCTIONS - CLEAN & SIMPLE
# ============================================================

def get_ip(host):
    """DNS lookup"""
    try:
        if ":" in host:
            host = host.split(":")[0]
        return socket.gethostbyname(host), "Live"
    except:
        return "0.0.0.0", "Blocked"

def get_geo(ip):
    """IP Geolocation"""
    if ip == "0.0.0.0":
        return None
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {
                    "country": d.get("country", "Unknown"),
                    "city": d.get("city", "Unknown"),
                    "isp": d.get("isp", "Unknown"),
                    "lat": d.get("lat"),
                    "lon": d.get("lon")
                }
    except:
        pass
    return None

def get_whois(domain):
    """WHOIS lookup"""
    if not WHOIS_AVAILABLE:
        return {"found": False, "error": "WHOIS not installed"}
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age = None
        if created:
            age = (datetime.datetime.utcnow() - created.replace(tzinfo=None)).days
        return {
            "found": True,
            "registrar": w.registrar or "Unknown",
            "created": str(created) if created else "Unknown",
            "age_days": age,
            "age_status": "New" if age and age < 30 else "Old" if age and age > 180 else "Medium"
        }
    except:
        return {"found": False, "error": "WHOIS failed"}

def get_redirects(url):
    """Follow redirects"""
    try:
        r = requests.get(url, timeout=6, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"})
        r.close()
        if r.history:
            return [h.url for h in r.history] + [r.url]
        return [r.url]
    except:
        return [url]

def extract_features(url):
    """Extract URL features"""
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    
    # Basic features
    length = len(host)
    has_at = 1 if "@" in host else 0
    subdomains = max(0, len(host.split('.')) - 2)
    has_dash = 1 if "-" in host else 0
    
    # Entropy
    probs = [host.count(c)/len(host) for c in set(host)] if host else [0]
    entropy = -sum([p * math.log(p,2) for p in probs if p > 0]) if host else 0
    
    # Suspicious keywords
    keywords = ['login','verify','secure','billing','update','paypal','amazon','auth']
    has_keyword = 1 if any(k in host for k in keywords) else 0
    
    # SSL
    is_ssl = 1 if parsed.scheme == 'https' else 0
    
    # IP masked
    is_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host.split(':')[0]) else 0
    
    features = [length, has_at, subdomains, has_dash, round(entropy,2), has_keyword]
    meta = {"is_ssl": is_ssl, "is_ip": is_ip}
    
    return features, host, meta

def scan_url(url):
    """Main scan function"""
    # Normalize URL
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    
    # Get redirects
    chain = get_redirects(url)
    final_url = chain[-1]
    
    # Extract features
    features, host, meta = extract_features(final_url)
    
    # DNS
    ip, status = get_ip(host)
    
    # Geo
    geo = get_geo(ip)
    
    # WHOIS
    whois = get_whois(host)
    
    # ML Prediction
    df = pd.DataFrame([features], columns=['length','has_at','subdomains','has_dash','entropy','has_token'])
    prob = model.predict_proba(df)[0][1]
    
    # Risk score
    risk = prob * 100
    if ip == "0.0.0.0":
        risk += 35
    if meta["is_ssl"] == 0:
        risk += 15
    if meta["is_ip"] == 1:
        risk += 40
    if whois.get("found") and whois.get("age_days"):
        if whois["age_days"] < 30:
            risk += 20
        elif whois["age_days"] < 180:
            risk += 8
    if len(chain) > 2:
        risk += 10
    
    risk = round(min(99, max(5, risk)), 1)
    safe = round(100 - risk, 1)
    malicious = risk >= 45
    
    return {
        "url": url,
        "final": final_url,
        "chain": chain,
        "host": host,
        "ip": ip,
        "status": status,
        "geo": geo,
        "whois": whois,
        "features": features,
        "meta": meta,
        "risk": risk,
        "safe": safe,
        "malicious": malicious,
        "time": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }

# ============================================================
# REPORT FUNCTIONS
# ============================================================

def get_csv(result):
    data = {
        "URL": result["url"],
        "Final": result["final"],
        "Verdict": "DANGEROUS" if result["malicious"] else "SAFE",
        "Risk %": result["risk"],
        "IP": result["ip"],
        "SSL": "Yes" if result["meta"]["is_ssl"] else "No",
        "Age (days)": result["whois"].get("age_days", "N/A"),
        "Country": result["geo"]["country"] if result["geo"] else "N/A"
    }
    buf = io.StringIO()
    pd.DataFrame([data]).to_csv(buf, index=False)
    return buf.getvalue().encode()

def get_pdf(result):
    buf = io.BytesIO()
    with PdfPages(buf) as pdf:
        fig, ax = plt.subplots(figsize=(8.27, 11.69))
        ax.axis("off")
        fig.patch.set_facecolor('white')
        
        lines = [
            "THREAT-X SCAN REPORT",
            "=" * 50,
            f"URL: {result['url']}",
            f"Final: {result['final']}",
            f"Verdict: {'DANGEROUS' if result['malicious'] else 'SAFE'}",
            f"Risk: {result['risk']}%",
            f"IP: {result['ip']}",
            f"SSL: {'Yes' if result['meta']['is_ssl'] else 'No'}",
            f"Time: {result['time']}"
        ]
        
        if result["whois"].get("found"):
            lines.append(f"Registrar: {result['whois']['registrar']}")
            lines.append(f"Age: {result['whois']['age_days']} days")
        
        if result["geo"]:
            lines.append(f"Country: {result['geo']['country']}")
            lines.append(f"City: {result['geo']['city']}")
        
        ax.text(0.02, 0.98, "\n".join(lines), va="top", ha="left", fontsize=10,
                family="monospace", transform=ax.transAxes)
        pdf.savefig(fig)
        plt.close(fig)
    return buf.getvalue()

# ============================================================
# UI - SINGLE SCAN
# ============================================================
tab1, tab2 = st.tabs(["🔍 Single Scan", "📂 Bulk Scan"])

with tab1:
    url = st.text_input("Enter website URL:", placeholder="https://example.com")
    
    if st.button("SCAN"):
        if url:
            try:
                result = scan_url(url)
                
                # ===== RESULTS =====
                st.write("---")
                st.write("### Results")
                
                # Metrics
                c1, c2, c3 = st.columns(3)
                if result["malicious"]:
                    c1.metric("Status", "⚠️ DANGEROUS", delta="RISK", delta_color="inverse")
                    c2.metric("Risk", f"{result['risk']}%", delta="HIGH", delta_color="inverse")
                    c3.metric("Safety", f"{result['safe']}%", delta="LOW", delta_color="inverse")
                else:
                    c1.metric("Status", "✅ SAFE")
                    c2.metric("Risk", f"{result['risk']}%", delta="LOW")
                    c3.metric("Safety", f"{result['safe']}%", delta="HIGH")
                
                st.write("---")
                
                # Pie chart
                fig, ax = plt.subplots(figsize=(6, 3))
                fig.patch.set_facecolor('#060814')
                ax.set_facecolor('#060814')
                colors = ['#00ffcc', '#ff3333'] if not result["malicious"] else ['#161c2e', '#ff3333']
                ax.pie([result["safe"], result["risk"]], 
                      labels=['Safe', 'Risk'],
                      colors=colors,
                      autopct='%1.1f%%',
                      textprops=dict(color='white', weight='bold'))
                st.pyplot(fig)
                plt.close(fig)
                
                st.write("---")
                
                # Details
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"🌐 **IP:** `{result['ip']}`")
                    st.write(f"🔌 **Status:** {result['status']}")
                    st.write(f"🔒 **SSL:** {'✅ Yes' if result['meta']['is_ssl'] else '❌ No'}")
                
                with col2:
                    st.write(f"🧠 **AI Score:** {round(result['features'][4], 2)}")
                    st.write(f"📊 **Risk:** {result['risk']}%")
                    st.write(f"🔄 **Redirects:** {len(result['chain'])-1}")
                
                st.write("---")
                
                # Redirect chain
                if len(result["chain"]) > 1:
                    st.write("#### Redirect Chain:")
                    for i, hop in enumerate(result["chain"]):
                        st.write(f"{i+1}. `{hop}`")
                
                st.write("---")
                
                # WHOIS
                if result["whois"].get("found"):
                    st.write("#### WHOIS:")
                    st.write(f"📅 **Registrar:** {result['whois']['registrar']}")
                    st.write(f"📆 **Created:** {result['whois']['created']}")
                    st.write(f"⏳ **Age:** {result['whois']['age_days']} days")
                    st.write(f"📊 **Status:** {result['whois']['age_status']}")
                
                st.write("---")
                
                # Geo
                if result["geo"]:
                    st.write("#### Geolocation:")
                    st.write(f"🌍 **Country:** {result['geo']['country']}")
                    st.write(f"🏙️ **City:** {result['geo']['city']}")
                    st.write(f"📡 **ISP:** {result['geo']['isp']}")
                
                st.write("---")
                
                # Download
                st.write("#### Download Report:")
                d1, d2 = st.columns(2)
                with d1:
                    st.download_button("PDF", get_pdf(result), 
                                     f"report_{result['host']}.pdf", "application/pdf")
                with d2:
                    st.download_button("CSV", get_csv(result),
                                     f"report_{result['host']}.csv", "text/csv")
                
            except Exception as e:
                st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter a URL")

# ============================================================
# UI - BULK SCAN
# ============================================================
with tab2:
    st.write("Upload CSV with 'url' column or paste URLs")
    
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    pasted = st.text_area("Or paste URLs (one per line)", height=100)
    
    if st.button("SCAN ALL"):
        urls = []
        
        if uploaded:
            try:
                df = pd.read_csv(uploaded)
                for col in df.columns:
                    if col.lower() == "url":
                        urls.extend(df[col].dropna().tolist())
                        break
            except:
                st.error("Invalid CSV")
        
        if pasted:
            urls.extend([u.strip() for u in pasted.splitlines() if u.strip()])
        
        urls = list(dict.fromkeys(urls))
        
        if not urls:
            st.warning("No URLs found")
        else:
            results = []
            st.info(f"Scanning {len(urls)} URLs...")
            
            for i, u in enumerate(urls):
                try:
                    r = scan_url(u)
                    results.append({
                        "URL": r["url"],
                        "Final": r["final"],
                        "Verdict": "DANGEROUS" if r["malicious"] else "SAFE",
                        "Risk %": r["risk"],
                        "IP": r["ip"],
                        "SSL": "Yes" if r["meta"]["is_ssl"] else "No",
                        "Age": r["whois"].get("age_days", "N/A"),
                        "Country": r["geo"]["country"] if r["geo"] else "N/A"
                    })
                except:
                    results.append({"URL": u, "Verdict": "FAILED"})
            
            df_results = pd.DataFrame(results)
            
            st.write("---")
            st.write(f"### Summary: {len(urls)} URLs")
            
            c1, c2, c3 = st.columns(3)
            dangerous = sum(1 for r in results if r.get("Verdict") == "DANGEROUS")
            safe = sum(1 for r in results if r.get("Verdict") == "SAFE")
            failed = sum(1 for r in results if r.get("Verdict") == "FAILED")
            c1.metric("⚠️ Dangerous", dangerous)
            c2.metric("✅ Safe", safe)
            c3.metric("❌ Failed", failed)
            
            st.dataframe(df_results)
            
            buf = io.StringIO()
            df_results.to_csv(buf, index=False)
            st.download_button("Download CSV", buf.getvalue().encode(), 
                             "bulk_results.csv", "text/csv")
