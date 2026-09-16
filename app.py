import streamlit as st
import requests
import json
import re
from urllib.parse import urlparse

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SentinelAI | Scam & Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(99,102,241,0.12), transparent 30%),
        radial-gradient(circle at 90% 10%, rgba(6,182,212,0.08), transparent 28%),
        #080b12;
    color: #f8fafc;
}

/* Sidebar */

section[data-testid="stSidebar"] {
    background: #0d111b;
    border-right: 1px solid #202938;
}

section[data-testid="stSidebar"] * {
    color: #e5e7eb;
}

/* Main container */

.block-container {
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}

/* Header */

.hero {
    padding: 25px 0 30px 0;
}

.logo {
    display: inline-flex;
    align-items: center;
    gap: 12px;
}

.logo-icon {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #6366f1, #06b6d4);
    font-size: 25px;
    box-shadow: 0 8px 30px rgba(99,102,241,0.25);
}

.hero-title {
    font-size: 38px;
    font-weight: 800;
    letter-spacing: -1.5px;
    margin: 0;
}

.hero-subtitle {
    color: #94a3b8;
    font-size: 15px;
    margin-top: 7px;
}

/* Cards */

.card {
    background: rgba(15, 23, 42, 0.82);
    border: 1px solid #263244;
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 18px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.18);
}

.card-title {
    font-size: 17px;
    font-weight: 700;
    margin-bottom: 5px;
}

.card-description {
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 18px;
}

/* Metrics */

.metric-card {
    background: #101827;
    border: 1px solid #273449;
    border-radius: 16px;
    padding: 20px;
    min-height: 115px;
}

.metric-label {
    color: #94a3b8;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
}

.metric-value {
    font-size: 27px;
    font-weight: 800;
    margin-top: 8px;
}

/* Risk */

.risk-high {
    border: 1px solid #ef4444;
    background: rgba(127, 29, 29, 0.18);
}

.risk-medium {
    border: 1px solid #f59e0b;
    background: rgba(120, 53, 15, 0.18);
}

.risk-low {
    border: 1px solid #22c55e;
    background: rgba(20, 83, 45, 0.18);
}

.risk-title {
    font-size: 30px;
    font-weight: 800;
}

.risk-score {
    font-size: 16px;
    color: #cbd5e1;
}

/* Red flags */

.flag {
    background: #111827;
    border: 1px solid #273449;
    border-radius: 12px;
    padding: 13px 15px;
    margin-bottom: 9px;
    font-size: 14px;
}

.flag-icon {
    margin-right: 8px;
}

/* Info */

.info-box {
    padding: 15px 17px;
    border-radius: 12px;
    background: rgba(59,130,246,0.08);
    border: 1px solid rgba(59,130,246,0.25);
    color: #cbd5e1;
    font-size: 13px;
}

/* Footer */

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding: 30px 0 10px;
}

/* Buttons */

.stButton > button {
    width: 100%;
    border-radius: 11px;
    border: 0;
    padding: 11px 20px;
    font-weight: 700;
    background: linear-gradient(135deg, #6366f1, #4f46e5);
    color: white;
    transition: 0.2s;
}

.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 8px 25px rgba(99,102,241,0.25);
}

/* Text areas */

textarea {
    background: #0b1220 !important;
    color: #f8fafc !important;
    border: 1px solid #293548 !important;
    border-radius: 12px !important;
}

/* Tabs */

button[data-baseweb="tab"] {
    font-weight: 600;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "scan_type" not in st.session_state:
    st.session_state.scan_type = "Message"


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown("""
    <div style="padding:10px 0 20px;">
        <div style="font-size:22px;font-weight:800;">🛡️ SentinelAI</div>
        <div style="color:#64748b;font-size:12px;margin-top:4px;">
            AI Scam & Phishing Detector
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### ⚙️ AI Configuration")

    api_key = st.text_input(
        "Groq API Key",
        type="password",
        placeholder="gsk_...",
        help="Your API key is used only for the current session."
    )

    model = st.selectbox(
        "AI Model",
        [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant"
        ]
    )

    st.markdown("---")

    st.markdown("### 🔐 What SentinelAI checks")

    st.markdown("""
    - 🚨 Urgency & pressure
    - 🔗 Suspicious URLs
    - 🔐 Credential requests
    - 💰 Financial manipulation
    - 🎁 Fake rewards
    - 👤 Impersonation
    - 📱 Social engineering
    """)

    st.markdown("---")

    st.markdown("""
    <div class="info-box">
    <b>Privacy note</b><br><br>
    Do not enter real passwords, OTPs, credit-card numbers,
    or other highly sensitive information.
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">

<div class="logo">
    <div class="logo-icon">🛡️</div>
    <div>
        <div class="hero-title">SentinelAI</div>
        <div class="hero-subtitle">
            Intelligent scam and phishing detection powered by GenAI
        </div>
    </div>
</div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# SCANNER TABS
# ============================================================

tab1, tab2 = st.tabs(["💬 Message Scanner", "🔗 URL Scanner"])


# ============================================================
# MESSAGE SCANNER
# ============================================================

with tab1:

    st.markdown("""
    <div class="card">
        <div class="card-title">🔍 Analyze a suspicious message</div>
        <div class="card-description">
            Paste an SMS, email, WhatsApp message, social-media message,
            job offer, banking alert, or any suspicious text.
        </div>
    </div>
    """, unsafe_allow_html=True)

    message = st.text_area(
        "Message",
        height=210,
        placeholder="""Example:

Congratulations! You have won Rs. 50,000.
Click the link below immediately to claim your prize.
You must provide your CNIC and bank account details
within 30 minutes or your reward will be cancelled.""",
        label_visibility="collapsed"
    )

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        analyze_message = st.button(
            "🔍 Analyze Message",
            key="analyze_message"
        )

    with col2:
        clear_message = st.button(
            "↻ Clear",
            key="clear_message"
        )

    if clear_message:
        st.session_state.analysis = None
        st.rerun()

    if analyze_message:

        if not message.strip():
            st.warning("Please enter a message to analyze.")

        elif not api_key:
            st.warning("Please enter your Groq API key in the sidebar.")

        else:
            with st.spinner("🧠 AI is analyzing the message..."):
                result = analyze_with_groq(
                    api_key,
                    model,
                    message,
                    "message"
                )

                if result:
                    st.session_state.analysis = result


# ============================================================
# URL SCANNER
# ============================================================

with tab2:

    st.markdown("""
    <div class="card">
        <div class="card-title">🔗 Analyze a suspicious URL</div>
        <div class="card-description">
            Enter a URL and SentinelAI will inspect its structure
            and ask the AI to assess potential phishing indicators.
        </div>
    </div>
    """, unsafe_allow_html=True)

    url = st.text_input(
        "URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed"
    )

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        analyze_url = st.button(
            "🔗 Analyze URL",
            key="analyze_url"
        )

    with col2:
        clear_url = st.button(
            "↻ Clear",
            key="clear_url"
        )

    if clear_url:
        st.session_state.analysis = None
        st.rerun()

    if analyze_url:

        if not url.strip():
            st.warning("Please enter a URL.")

        elif not api_key:
            st.warning("Please enter your Groq API key in the sidebar.")

        else:
            url_info = inspect_url(url)

            with st.spinner("🧠 AI is analyzing the URL..."):
                result = analyze_with_groq(
                    api_key,
                    model,
                    url,
                    "url",
                    url_info
                )

                if result:
                    st.session_state.analysis = result


# ============================================================
# DISPLAY RESULTS
# ============================================================

if st.session_state.analysis:

    result = st.session_state.analysis

    st.markdown("---")

    st.markdown("""
    <div style="margin:25px 0 15px;">
        <div style="font-size:24px;font-weight:800;">📊 Security Analysis</div>
        <div style="color:#94a3b8;font-size:13px;">
            AI-generated assessment based on the submitted content.
        </div>
    </div>
    """, unsafe_allow_html=True)

    risk = str(result.get("risk_level", "UNKNOWN")).upper()

    try:
        score = int(result.get("risk_score", 0))
    except:
        score = 0

    category = result.get("category", "Unknown")
    summary = result.get("summary", "No summary available.")
    recommendation = result.get(
        "recommendation",
        "Verify the message through an independent trusted source."
    )

    if risk == "HIGH":
        risk_class = "risk-high"
        risk_icon = "🔴"
    elif risk == "MEDIUM":
        risk_class = "risk-medium"
        risk_icon = "🟠"
    else:
        risk_class = "risk-low"
        risk_icon = "🟢"

    # Top metrics

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Risk level</div>
            <div class="metric-value">{risk_icon} {risk}</div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Risk score</div>
            <div class="metric-value">{score}/100</div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Detected category</div>
            <div class="metric-value" style="font-size:21px;">
                {category}
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Risk banner

    st.markdown(f"""
    <div class="card {risk_class}">
        <div class="risk-title">
            {risk_icon} {risk} RISK
        </div>
        <div class="risk-score">
            AI assessment score: <b>{score}/100</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

    left, right = st.columns(2)

    # Red flags

    with left:

        st.markdown("""
        <div class="card">
            <div class="card-title">🚩 Detected Red Flags</div>
            <div class="card-description">
                Suspicious indicators identified by the AI.
            </div>
        """, unsafe_allow_html=True)

        flags = result.get("red_flags", [])

        if isinstance(flags, str):
            flags = [flags]

        if not flags:
            flags = ["No specific red flags were identified."]

        for flag in flags:
            st.markdown(
                f"""
                <div class="flag">
                    <span class="flag-icon">⚠️</span>{flag}
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("</div>", unsafe_allow_html=True)

    # Explanation

    with right:

        st.markdown("""
        <div class="card">
            <div class="card-title">🧠 AI Explanation</div>
            <div class="card-description">
                Why the content received this assessment.
            </div>
        """, unsafe_allow_html=True)

        st.markdown(
            f'<div style="color:#cbd5e1;line-height:1.7;">{summary}</div>',
            unsafe_allow_html=True
        )

        st.markdown("</div>", unsafe_allow_html=True)

    # Recommendation

    st.markdown(f"""
    <div class="card">
        <div class="card-title">🛡️ Recommended Action</div>
        <div class="card-description">
            What you should consider doing next.
        </div>

        <div class="info-box">
            {recommendation}
        </div>
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# FOOTER
# ============================================================

st.markdown("""
<div class="footer">
    🛡️ SentinelAI &nbsp;•&nbsp; AI Scam & Phishing Detector
    <br><br>
    AI analysis can make mistakes. Always independently verify
    suspicious communications through trusted official channels.
</div>
""", unsafe_allow_html=True)


# ============================================================
# URL INSPECTION
# ============================================================

def inspect_url(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        suspicious_keywords = [
            "login",
            "verify",
            "verification",
            "account",
            "secure",
            "update",
            "password",
            "bank",
            "wallet",
            "payment",
            "bonus",
            "reward",
            "claim"
        ]

        keyword_matches = [
            word for word in suspicious_keywords
            if word in url.lower()
        ]

        looks_like_ip = bool(
            re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$",
                hostname
            )
        )

        return {
            "normalized_url": url,
            "domain": hostname,
            "https": parsed.scheme == "https",
            "url_length": len(url),
            "subdomains": len(hostname.split(".")) - 2,
            "looks_like_ip": looks_like_ip,
            "suspicious_keywords": keyword_matches,
            "has_at_symbol": "@" in url,
            "has_many_hyphens": hostname.count("-") >= 3
        }

    except Exception:
        return {
            "normalized_url": url,
            "error": "Could not parse URL."
        }


# ============================================================
# GROQ AI ANALYSIS
# ============================================================

def analyze_with_groq(api_key, model, content, content_type, url_info=None):

    if content_type == "message":

        task = f"""
Analyze the following message for scam/phishing risk.

MESSAGE:
{content}
"""

    else:

        task = f"""
Analyze the following URL for possible phishing/scam risk.

URL:
{content}

URL STRUCTURAL INFORMATION:
{json.dumps(url_info, indent=2)}
"""

    system_prompt = """
You are a cybersecurity threat-analysis assistant.

Analyze user-provided messages or URLs for possible scam,
phishing, fraud, impersonation, social engineering, or other
malicious indicators.

Return ONLY valid JSON.

Use this exact structure:

{
  "risk_level": "HIGH | MEDIUM | LOW",
  "risk_score": 0,
  "category": "Phishing | Scam | Spam | Legitimate | Suspicious URL | Other",
  "red_flags": [
    "short reason 1",
    "short reason 2"
  ],
  "summary": "A concise explanation of the assessment.",
  "recommendation": "A practical safety recommendation."
}

Rules:

- risk_score must be an integer from 0 to 100.
- HIGH generally means strong indicators of malicious or fraudulent intent.
- MEDIUM means suspicious indicators exist but the evidence is not conclusive.
- LOW means there are few obvious scam/phishing indicators.
- Do not claim certainty when the evidence is uncertain.
- Do not visit or execute any URL.
- Do not ask the user to provide passwords, OTPs, API keys, credit-card
  numbers, or other secrets.
- Keep red_flags concise and useful.
- Focus on observable characteristics rather than speculation.
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": task
            }
        ],
        "temperature": 0.2,
        "max_tokens": 700
    }

    try:

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=60
        )

        if response.status_code != 200:

            try:
                error_message = response.json().get(
                    "error",
                    {}
                ).get(
                    "message",
                    response.text
                )
            except:
                error_message = response.text

            st.error(
                f"Groq API error ({response.status_code}): "
                f"{error_message}"
            )

            return None

        data = response.json()

        content = data["choices"][0]["message"]["content"]

        # Remove markdown JSON fences if model adds them

        content = content.strip()

        if content.startswith("```"):
            content = re.sub(
                r"^```(?:json)?",
                "",
                content
            )
            content = re.sub(
                r"```$",
                "",
                content
            ).strip()

        result = json.loads(content)

        return result

    except requests.exceptions.Timeout:

        st.error(
            "The AI request timed out. Please try again."
        )

        return None

    except json.JSONDecodeError:

        st.error(
            "The AI returned an unexpected response. "
            "Please try the analysis again."
        )

        return None

    except Exception as e:

        st.error(
            f"Something went wrong while analyzing the content: {e}"
        )

        return None
