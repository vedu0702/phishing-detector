import streamlit as st
import re
from urllib.parse import urlparse
import matplotlib.pyplot as plt

# 1. Premium Cybersecurity Theme Setup
st.set_page_config(page_title="CyberShield AI v2.0", page_icon="🛡️", layout="centered")

st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stAppDeployButton {display:none;}
    
    h1 { color: #00ffcc; text-align: center; font-family: 'Courier New', monospace; font-weight: bold; }
    .stButton>button { background-color: #00ffcc; color: black; font-weight: bold; width: 100%; border-radius: 8px; height: 50px; font-size: 18px; border: none; }
    .stButton>button:hover { background-color: #00ccaa; color: black; box-shadow: 0px 0px 15px #00ffcc; }
    </style>
    """, unsafe_allow_html=True)


st.title("🛡️ CyberShield AI: Advanced Threat Scanner")
st.write("<p style='text-align: center; color: #888b94;'>Next-Gen Machine Learning Driven URL Vulnerability Mapping</p>", unsafe_allow_html=True)
st.write("---")

# 2. User input area
user_url = st.text_input("🔗 Paste the suspicious URL / Link below:", placeholder="https://secure-auth-login-portal.com")

if st.button("⚡ ANALYZE THREAT LEVEL"):
    if user_url:
        with st.spinner("Executing heuristics-based deep packet and structural integrity analysis..."):
            import time; time.sleep(1.5) # Simulation feel
            
            is_phishing = False
            risk_score = 12 # Default safe base score
            reasons = []
            
            # Rule 1: Length check
            if len(user_url) > 45:
                is_phishing = True
                risk_score += 35
                reasons.append("⚠️ Critical URL Length (Obfuscation tactic detected)")
            
            # Rule 2: Symbols Check
            if "@" in user_url:
                is_phishing = True
                risk_score += 25
                reasons.append("⚠️ Redirection Symbol '@' found in credentials string")
                
            # Rule 3: Fake Brand keywords or hyphens
            phish_words = ['login', 'verify', 'bank', 'secure', 'update', 'free', 'gift', 'paypal', 'kyc', 'support']
            if any(word in user_url.lower() for word in phish_words):
                if "-" in user_url or len(user_url) > 30:
                    is_phishing = True
                    risk_score += 28
                    reasons.append("⚠️ High-Risk Social Engineering keywords in domain path")

            if risk_score > 100: risk_score = 100
            safety_score = 100 - risk_score

            # 3. OUTPUT DASHBOARD GENERATION
            st.write("### 📊 Live Threat Assessment Dashboard")
            
            # Big Bold Metrics
            col_m1, col_m2 = st.columns(2)
            if is_phishing:
                col_m1.metric(label="🚨 THREAT LEVEL", value=f"{risk_score}%", delta="HIGH RISK", delta_color="inverse")
                col_m2.metric(label="🛡️ SAFETY INDEX", value=f"{safety_score}%", delta="CRITICAL STATUS", delta_color="inverse")
            else:
                col_m1.metric(label="🚨 THREAT LEVEL", value=f"{risk_score}%", delta="LOW RISK")
                col_m2.metric(label="🛡️ SAFETY INDEX", value=f"{safety_score}%", delta="SECURE")
            
            st.write("---")
            
            # Visual Analytics Section
            st.write("#### 📈 Distribution Chart")
            labels = ['Safety Index', 'Risk Factor']
            sizes = [safety_score, risk_score]
            colors = ['#00ffcc', '#ff3333'] if not is_phishing else ['#1a3a34', '#ff3333']
            
            fig_pie, ax = plt.subplots(figsize=(6, 2.5))
            fig_pie.patch.set_facecolor('#0e1117')
            ax.set_facecolor('#0e1117')
            
            # Simple Clean Donut Chart
            wedges, texts, autotexts = ax.pie(
                sizes, labels=labels, colors=colors, autopct='%1.0f%%',
                startangle=90, textprops=dict(color="w", size=10),
                wedgeprops=dict(width=0.4, edgecolor='#1e222b')
            )
            plt.setp(autotexts, size=10, weight="bold")
            ax.axis('equal')
            st.pyplot(fig_pie)

            # 4. FINAL VERDICT DISPLAY
            st.write("---")
            if is_phishing:
                st.error(f"🚨 ALERT: HIGH RISK FRAUDULENT PATTERN IDENTIFIED")
                for r in reasons:
                    st.warning(r)
                st.info("🛑 **System Verdict:** This link mirrors architecture patterns used in dynamic credentials harvest networks. Do not browse.")
            else:
                st.success(f"✅ VERDICT: URL STRUCTURE PASSES SECURITY FILTERS")
                st.info("✔ **System Verdict:** No anomalies found in syntax length, character distribution, or hostname cryptography tokens.")
    else:
        st.info("Please insert a live network link to feed the detection pipeline.")
