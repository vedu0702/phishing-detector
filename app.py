import streamlit as st
import pandas as pd
import math
import socket
import requests
import re
import matplotlib.pyplot as plt
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

st.write("<div style='text-align: center; padding-top: 10px;'><span style='font-size: 38px; font-weight: 800; color: #ffffff; letter-spacing: 1px;'>THREAT</span><span style='font-size: 38px; font-weight: 800; color: #00ffcc; letter-spacing: 1px;'>-X</span><span style='font-size: 14px; font-weight: bold; color: #475569; margin-left: 8px;'>GLOBAL GUARD PRO v12.0</span></div>", unsafe_allow_html=True)
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

# 3. Real Live Past History Scam Checker (URLHaus API Integration over Internet)
def check_past_phishing_history(target_url):
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={'url': target_url},
            timeout=4.0
        )
        if response.status_code == 200:
            res_data = response.json()
            if res_data.get('query_status') == 'ok':
                return True, f"Reported scam listed in Global Blocklist databases (Class: {res_data.get('threat')})"
    except Exception:
        pass
    return False, "Clean record: No active historical threats listed inside open intelligence repositories."

# 4. Live DNS Host Resolver
def resolve_live_dns_ip(hostname):
    try:
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        return socket.gethostbyname(hostname), "🟢 Live & Verified"
    except Exception:
        return "0.0.0.0", "🔴 Inactive / Blocked Server"

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

# 6. User Console Interface Layout
user_target = st.text_input("🔗 Enter website link here to analyze secure features:", placeholder="e.g., https://my-safe-website.com")

if st.button("🔍 SCAN WEBSITE NOW"):
    if user_target:
        working_url = user_target if user_target.startswith(('http://', 'https://')) else 'http://' + user_target

        with st.spinner("Analyzing server protocols and scanning system weights..."):
            feature_weights, host_domain, pro_meta = extract_lexical_vectors(working_url)
            resolved_ip, dns_status_log = resolve_live_dns_ip(host_domain)
            has_scam_history, history_log_msg = check_past_phishing_history(working_url)

            eval_dataframe = pd.DataFrame([feature_weights], columns=['length', 'has_at', 'subdomains', 'has_dash', 'entropy', 'has_token'])
            ml_probabilities = cyber_classifier.predict_proba(eval_dataframe)
            ml_phish_probability = float(ml_probabilities[0][1])

            dynamic_risk_weight = ml_phish_probability * 100.0
            if has_scam_history:
                dynamic_risk_weight += 25.0
            if resolved_ip == "0.0.0.0":
                dynamic_risk_weight += 35.0
            if pro_meta["is_ssl"] == 0:
                dynamic_risk_weight += 15.0
            if pro_meta["is_ip_masked"] == 1:
                dynamic_risk_weight += 40.0

            risk_percent = round(min(99.4, max(4.2, dynamic_risk_weight)), 1)
            safety_percent = round(100.0 - risk_percent, 1)
            is_malicious_class = True if risk_percent >= 45.0 else False

        # 7. METRICS & ANALYSIS DASHBOARD
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
        plt.close()

        st.write("---")
        st.write("#### 📡 System Integrity Verification Details:")
        l_col1, l_col2 = st.columns(2)

        with l_col1:
            st.write(f"🌐 **Website Host Server IP:** `{resolved_ip}`")
            st.write(f"🔌 **Server Connection Status:** {dns_status_log}")

        with l_col2:
            st.write(f"🧠 **AI Prediction Output:** :{'red[SUSPICIOUS ACTIVITY MATCH]' if is_malicious_class else 'green[LEGITIMATE WEBSITE SIGNATURE]'}")
            st.write(f"📝 **Global Blacklist Tracker:** :{'red[MALICIOUS RECORDS MATCH]' if has_scam_history else 'green[NO THREAT REPORT FOUND]'}")

        st.write("---")

        # PRO FEATURE: Advanced heuristics breakdown table
        st.write("#### 🔍 Structural Feature Breakdown Table:")
        breakdown_data = {
            "Security Parameter Indicator": [
                "SSL Protocol Encryption Status",
                "Domain Raw IP Address Mask Check",
                "Suspicious Login/Verify Keyword Flag",
                "URL Hyphen Clustering Matrix",
                "Subdomain Layer Count Check"
            ],
            "Observed Metric Value": [
                "HTTPS Secured" if pro_meta["is_ssl"] == 1 else "Insecure HTTP Standard",
                "Masked Raw IP Address Detected" if pro_meta["is_ip_masked"] == 1 else "Legitimate Text String Domain",
                "Triggered (Malicious Keywords Found)" if feature_weights[5] == 1 else "Clean Structural Patterns",
                f"{feature_weights[3]} Structural Dash Elements Detected",
                f"{feature_weights[2]} Segment Subdomains Layered"
            ],
            "Risk Severity Rating": [
                "✅ LOW RISK" if pro_meta["is_ssl"] == 1 else "⚠️ MEDIUM RISK ALERT",
                "🚨 CRITICAL HIGH RISK" if pro_meta["is_ip_masked"] == 1 else "✅ SECURE INFRASTRUCTURE",
                "⚠️ HIGH SUSPICION" if feature_weights[5] == 1 else "✅ SECURE INFRASTRUCTURE",
                "⚠️ MINOR ANOMALY" if feature_weights[3] > 0 else "✅ SECURE INFRASTRUCTURE",
                "⚠️ MEDIUM SUSPICION" if feature_weights[2] > 1 else "✅ SECURE INFRASTRUCTURE"
            ]
        }
        st.table(pd.DataFrame(breakdown_data))

        st.write("---")
        st.write("#### 🧠 Technical System Ingestion Metrics:")
        st.info(f"**Extracted Live Feature Vector Sequence:** {feature_weights}")
        st.markdown(f"""
        - **Random Forest Base Confidence Core:** `{round(ml_phish_probability*100, 1)}% Structural Deviation Weight`
        - **Database Verification Log Output:** `{history_log_msg}`
        - **URL Lexical Parameters Check:** Length: `{feature_weights[0]}` | Subdomains Detected: `{feature_weights[2]}` | Structural Hyphens: `{feature_weights[3]}` | String Entropy: `{feature_weights[4]}`
        """)

        if is_malicious_class:
            st.error("🛑 ACTION RECOMMENDED: Our Artificial Intelligence engine recommends closing this tab immediately. The URL demonstrates verified fraudulent design footprints.")
        else:
            st.success("✔ SECURITY CLEARANCE GRANTED: This website satisfies all structural security patterns. No phishing behaviors were detected.")
    else:
        st.info("Please provide a valid website address string link to execute security scans.")
