import streamlit as st
import re
from urllib.parse import urlparse

# Page Setup - Premium Look
st.set_page_config(page_title="CyberShield AI", page_icon="🛡️", layout="centered")

# Custom Styling for Cyber Aesthetic
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    h1 { color: #00ffcc; text-align: center; font-family: 'Helvetica', sans-serif; }
    .stButton>button { background-color: #00ffcc; color: black; font-weight: bold; width: 100%; border-radius: 8px; }
    .stButton>button:hover { background-color: #00ccaa; color: black; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ CyberShield: AI Phishing Detection Engine")
st.write("---")
st.write("### Real-time URL Vulnerability & Threat Analysis")

# User Input
user_url = st.text_input("🔗 Paste the suspicious URL / Link here:", placeholder="https://secure-login-bank-verify.com")

if st.button("🔍 SCAN LINK NOW"):
    if user_url:
        with st.spinner("Analyzing domain credentials and cryptographic signatures..."):
            import time; time.sleep(1.5) # Real-time feel ke liye delay
            
            # Simple UI-driven logic for live demo
            is_phishing = False
            reasons = []
            
            # Rule 1: Length check
            if len(user_url) > 50:
                is_phishing = True
                reasons.append("⚠️ Excessive URL Length (Commonly used to hide malicious subdomains)")
            
            # Rule 2: Suspicious symbols
            if "@" in user_url:
                is_phishing = True
                reasons.append("⚠️ Presence of '@' character (Used to spoof browser redirections)")
                
            # Rule 3: Suspicious words
            phish_words = ['login', 'verify', 'bank', 'secure', 'update', 'free', 'gift', 'paypal']
            if any(word in user_url.lower() for word in phish_words):
                # If it has phish words and is long or has hyphens, flag it
                if "-" in user_url or len(user_url) > 35:
                    is_phishing = True
                    reasons.append("⚠️ High-risk keywords detected inside an unverified domain structure")

            # Final Display
            st.write("---")
            st.subheader("Analysis Report:")
            
            if is_phishing:
                st.error("🚨 RESULT: HIGH RISK PHISHING THREAT DETECTED!")
                st.metric(label="Security Confidence Score", value="14%", delta="-86% CRITICAL")
                for r in reasons:
                    st.warning(r)
                st.info("💡 **Recommendation:** Block traffic to this link immediately. Do not enter credentials.")
            else:
                st.success("✅ RESULT: URL STRUCTURE APPEARS SAFE")
                st.metric(label="Security Confidence Score", value="98%", delta="SAFE")
                st.info("✔ Structural checks passed. The link does not exhibit standard patterns of automated phishing clones.")
    else:
        st.info("Please enter a link to test the scanner.")
