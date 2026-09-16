import streamlit as st
import requests
import json
import re
from urllib.parse import urlparse


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="SentinelAI | Scam & Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background: #080b12;
    color: #f1f5f9;
}

[data-testid="stSidebar"] {
    background: #0d111b;
    border-right: 1px solid #1e293b;
}

[data-testid="stSidebar"] * {
    color: #e2e8f0;
}

.block-container {
    max-width: 1200px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* Brand */

.brand-title {
    font-size: 25px;
    font-weight: 800;
    margin-bottom: 3px;
}

.brand-subtitle {
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 25px;
}

/* Hero */

.hero {
    background: linear-gradient(135deg, #111827, #0b1220);
    border: 1px solid #243044;
    border-radius: 20px;
    padding: 30px;
    margin-bottom: 25px;
}

.hero-title {
    font-size: 38px;
    font-weight: 800;
    margin-bottom: 5px;
}

.hero-subtitle {
    color: #94a3b8;
    font-size: 16px;
}

.hero-icon {
    font-size: 45px;
    margin-bottom: 5px;
}

/* Cards */

.card {
    background: #101621;
    border: 1px solid #243044;
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 20px;
}

.card-title {
    font-size: 21px;
    font-weight: 700;
    margin-bottom: 7px;
}

.card-description {
    color: #94a3b8;
    font-size: 14px;
    line-height: 1.6;
}

/* Metrics */

.metric-card {
    background: #101621;
    border: 1px solid #243044;
    border-radius: 14px;
    padding: 20px;
    text-align: center;
}

.metric-label {
    color: #94a3b8;
    font-size: 13px;
}

.metric-value {
    font-size: 25px;
    font-weight: 800;
    margin-top: 5px;
}

/* Result */

.result-box {
    background: #0d1420;
    border: 1px solid #293548;
    border-radius: 16px;
    padding: 25px;
    margin-top: 20px;
}

.red-flag {
    background: #24141a;
    border-left: 4px solid #ef4444;
    padding: 12px 15px;
    border-radius: 7px;
    margin-bottom: 8px;
}

.info-box {
    background: #101c2d;
    border-left: 4px solid #3b82f6;
    padding: 15px;
    border-radius: 7px;
    line-height: 1.6;
}

.warning-box {
    background: #211b0d;
    border-left: 4px solid #f59e0b;
    padding: 15px;
    border-radius: 7px;
}

/* Footer */

.footer {
    text-align: center;
    color: #64748b;
    font-size: 12px;
    padding-top: 30px;
}

/* Buttons */

.stButton > button {
    border-radius: 9px;
    font-weight: 600;
    min-height: 45px;
}

/* Text area */

textarea {
    background-color: #0b111b !important;
    color: #f8fafc !important;
}

/* Input */

input {
    background-color: #0b111b !important;
    color: #f8fafc !important;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# URL INSPECTION
# =========================================================

def inspect_url(url):

    original_url = url.strip()

    if not original_url:
        return {}

    normalized_url = original_url

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""

    suspicious_words = [
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
        "claim",
        "signin",
        "confirm",
        "security"
    ]

    found_words = [
        word for word in suspicious_words
        if word in original_url.lower()
    ]

    ip_address = bool(
        re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            hostname
        )
    )

    subdomains = hostname.count(".")

    return {
        "hostname": hostname,
        "https": normalized_url.startswith("https://"),
        "length": len(original_url),
        "subdomains": subdomains,
        "ip_address": ip_address,
        "at_symbol": "@" in original_url,
        "many_hyphens": original_url.count("-") >= 3,
        "suspicious_words": found_words
    }


# =========================================================
# GROQ AI ANALYSIS
# =========================================================

def analyze_with_groq(
    api_key,
    model,
    content,
    content_type,
    url_info=None
):

    if not api_key:
        return {
            "error": "Please enter your Groq API key in the sidebar."
        }

    system_prompt = """
You are SentinelAI, an AI cybersecurity assistant specialized
in detecting scams, phishing, social engineering and suspicious URLs.

Analyze the provided content carefully.

Return ONLY valid JSON.

Use this exact structure:

{
  "risk_level": "HIGH",
  "risk_score": 90,
  "category": "Phishing",
  "red_flags": [
    "Creates urgency",
    "Requests sensitive information"
  ],
  "summary": "Short explanation of the assessment.",
  "recommendation": "Practical safety recommendation."
}

Rules:

risk_level must be one of:
HIGH, MEDIUM, LOW

risk_score must be an integer from 0 to 100.

category should be one of:
Phishing
Scam
Spam
Legitimate
Suspicious URL
Job Scam
Financial Scam
Other

red_flags must be a list of short points.

Do not request passwords, OTPs, credit card numbers,
or other sensitive information.

Do not visit or execute any provided URL.

Base your assessment only on the content provided.
"""

    user_prompt = f"""
Content type: {content_type}

Content:

{content}
"""

    if url_info:
        user_prompt += f"""

Technical URL indicators:

{json.dumps(url_info, indent=2)}
"""

    try:

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "temperature": 0.1,
                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": user_prompt
                    }
                ]
            },
            timeout=60
        )

        if response.status_code != 200:
            return {
                "error": f"Groq API error: {response.status_code}\n{response.text}"
            }

        data = response.json()

        result = data["choices"][0]["message"]["content"]

        result = result.strip()

        # Remove markdown JSON fences if model adds them

        if result.startswith("```"):
            result = re.sub(
                r"```json|```",
                "",
                result
            ).strip()

        return json.loads(result)

    except json.JSONDecodeError:

        return {
            "error": "The AI returned an invalid response. Please try again."
        }

    except requests.exceptions.Timeout:

        return {
            "error": "The request timed out. Please try again."
        }

    except Exception as e:

        return {
            "error": f"Something went wrong: {str(e)}"
        }


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown(
        '<div class="brand-title">🛡️ SentinelAI</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="brand-subtitle">Scam & Phishing Intelligence</div>',
        unsafe_allow_html=True
    )

    st.divider()

    st.subheader("⚙️ AI Configuration")

    api_key = st.text_input(
        "Groq API Key",
        type="password",
        placeholder="Enter your Groq API key"
    )

    model = st.selectbox(
        "AI Model",
        [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant"
        ]
    )

    st.divider()

    st.subheader("🔎 Detection Signals")

    signals = [
        "🚨 Urgency & pressure",
        "🔗 Suspicious URLs",
        "🔐 Credential requests",
        "💰 Financial manipulation",
        "🎁 Fake rewards",
        "👤 Impersonation",
        "📱 Social engineering"
    ]

    for signal in signals:
        st.write(signal)

    st.divider()

    st.subheader("🔒 Privacy")

    st.caption(
        "Do not enter real passwords, OTPs, "
        "credit-card numbers, or other sensitive information."
    )


# =========================================================
# HERO
# =========================================================

st.markdown(
    '<div class="hero-icon">🛡️</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="hero-title">SentinelAI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="hero-subtitle">'
    'Intelligent scam and phishing detection powered by Generative AI'
    '</div>',
    unsafe_allow_html=True
)

st.write("")


# =========================================================
# TABS
# =========================================================

message_tab, url_tab = st.tabs(
    ["💬 Message Scanner", "🔗 URL Scanner"]
)


# =========================================================
# MESSAGE SCANNER
# =========================================================

with message_tab:

    st.markdown(
        '<div class="card-title">🔍 Analyze a suspicious message</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="card-description">'
        'Analyze SMS messages, emails, WhatsApp messages, job offers, '
        'banking alerts, social-media messages, and other suspicious content.'
        '</div>',
        unsafe_allow_html=True
    )

    st.write("")

    message = st.text_area(
        "Suspicious message",
        height=220,
        placeholder=(
            "Paste a suspicious SMS, email, job offer, "
            "banking message, or social-media message here..."
        ),
        label_visibility="collapsed"
    )

    col1, col2 = st.columns([3, 1])

    with col1:

        analyze_message = st.button(
            "🛡️ Analyze Message",
            use_container_width=True
        )

    with col2:

        clear_message = st.button(
            "Clear",
            use_container_width=True
        )

    if clear_message:
        st.rerun()

    if analyze_message:

        if not message.strip():

            st.warning("Please enter a message first.")

        elif not api_key:

            st.error("Please enter your Groq API key in the sidebar.")

        else:

            with st.spinner("SentinelAI is analyzing the message..."):

                result = analyze_with_groq(
                    api_key,
                    model,
                    message,
                    "Suspicious message"
                )

            st.session_state["analysis"] = result


# =========================================================
# URL SCANNER
# =========================================================

with url_tab:

    st.markdown(
        '<div class="card-title">🔗 Inspect a suspicious URL</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="card-description">'
        'Check a URL for suspicious structural indicators and let AI '
        'assess the potential risk.'
        '</div>',
        unsafe_allow_html=True
    )

    st.write("")

    url = st.text_input(
        "Suspicious URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed"
    )

    col1, col2 = st.columns([3, 1])

    with col1:

        analyze_url_button = st.button(
            "🔍 Analyze URL",
            use_container_width=True
        )

    with col2:

        clear_url = st.button(
            "Clear",
            use_container_width=True,
            key="clear_url"
        )

    if clear_url:
        st.rerun()

    if analyze_url_button:

        if not url.strip():

            st.warning("Please enter a URL first.")

        elif not api_key:

            st.error("Please enter your Groq API key in the sidebar.")

        else:

            url_info = inspect_url(url)

            with st.spinner("SentinelAI is inspecting the URL..."):

                result = analyze_with_groq(
                    api_key,
                    model,
                    url,
                    "URL",
                    url_info
                )

            st.session_state["analysis"] = result


# =========================================================
# RESULTS
# =========================================================

if "analysis" in st.session_state:

    result = st.session_state["analysis"]

    st.divider()

    st.subheader("📊 Analysis Result")

    if "error" in result:

        st.error(result["error"])

    else:

        risk_level = str(
            result.get("risk_level", "UNKNOWN")
        ).upper()

        risk_score = int(
            result.get("risk_score", 0)
        )

        category = result.get(
            "category",
            "Unknown"
        )

        # -------------------------------------------------
        # METRICS
        # -------------------------------------------------

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Risk Level",
                risk_level
            )

        with col2:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with col3:

            st.metric(
                "Category",
                category
            )

        st.write("")

        # -------------------------------------------------
        # PROGRESS
        # -------------------------------------------------

        st.progress(
            min(max(risk_score, 0), 100) / 100,
            text=f"Risk score: {risk_score}/100"
        )

        # -------------------------------------------------
        # RISK MESSAGE
        # -------------------------------------------------

        if risk_level == "HIGH":

            st.error(
                "🚨 HIGH RISK — This content contains strong "
                "indicators of a scam or phishing attempt."
            )

        elif risk_level == "MEDIUM":

            st.warning(
                "⚠️ MEDIUM RISK — This content contains "
                "some suspicious indicators."
            )

        else:

            st.success(
                "✅ LOW RISK — No major scam indicators "
                "were identified."
            )

        # -------------------------------------------------
        # RED FLAGS
        # -------------------------------------------------

        st.subheader("🚩 Detected Red Flags")

        red_flags = result.get(
            "red_flags",
            []
        )

        if red_flags:

            for flag in red_flags:

                st.markdown(
                    f"""
                    <div class="red-flag">
                    🚩 {flag}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        else:

            st.info("No specific red flags were identified.")

        # -------------------------------------------------
        # EXPLANATION
        # -------------------------------------------------

        st.subheader("🧠 AI Explanation")

        st.markdown(
            f"""
            <div class="info-box">
            {result.get("summary", "No explanation available.")}
            </div>
            """,
            unsafe_allow_html=True
        )

        # -------------------------------------------------
        # RECOMMENDATION
        # -------------------------------------------------

        st.subheader("🛡️ Recommended Action")

        st.markdown(
            f"""
            <div class="warning-box">
            {result.get("recommendation", "Exercise caution.")}
            </div>
            """,
            unsafe_allow_html=True
        )


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.markdown(
    """
    <div class="footer">
        🛡️ SentinelAI &nbsp;•&nbsp;
        AI Scam & Phishing Detector
        <br><br>
        AI analysis may occasionally be incorrect.
        Always verify suspicious communications through trusted official channels.
    </div>
    """,
    unsafe_allow_html=True
)
