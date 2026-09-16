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
# FUNCTIONS
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
            "claim",
            "signin",
            "confirm"
        ]

        keyword_matches = [
            word
            for word in suspicious_keywords
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
            "subdomains": max(
                0,
                len(hostname.split(".")) - 2
            ),
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


def analyze_with_groq(
    api_key,
    model,
    content,
    content_type,
    url_info=None
):

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
You are SentinelAI, a cybersecurity threat-analysis assistant.

Analyze user-provided messages or URLs for:

- scams
- phishing
- spam
- impersonation
- fraud
- social engineering
- suspicious URLs

Return ONLY valid JSON.

Use exactly this structure:

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

1. risk_level must be exactly:
HIGH, MEDIUM, or LOW.

2. risk_score must be an integer from 0 to 100.

3. category should be one of:
Phishing
Scam
Spam
Legitimate
Suspicious URL
Job Scam
Financial Scam
Other

4. Give 2-5 concise red flags when appropriate.

5. Explain the decision using observable characteristics.

6. Do not claim certainty when evidence is uncertain.

7. Never ask the user for passwords, OTPs, API keys,
credit-card numbers, or other secrets.

8. Never visit or execute URLs.

9. Keep explanations concise.

10. Return ONLY JSON.
Do not use markdown.
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

                error_message = (
                    response
                    .json()
                    .get("error", {})
                    .get("message", response.text)
                )

            except Exception:

                error_message = response.text

            st.error(
                f"Groq API error ({response.status_code}): "
                f"{error_message}"
            )

            return None

        data = response.json()

        ai_content = (
            data["choices"][0]["message"]["content"]
            .strip()
        )

        if ai_content.startswith("```"):

            ai_content = re.sub(
                r"^```(?:json)?",
                "",
                ai_content
            )

            ai_content = re.sub(
                r"```$",
                "",
                ai_content
            ).strip()

        return json.loads(ai_content)

    except requests.exceptions.Timeout:

        st.error(
            "The AI request timed out. Please try again."
        )

        return None

    except json.JSONDecodeError:

        st.error(
            "The AI returned an unexpected response. "
            "Please try again."
        )

        return None

    except Exception as e:

        st.error(
            f"Something went wrong: {e}"
        )

        return None


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    /* =========================
       GLOBAL
       ========================= */

    .stApp {
        background:
            radial-gradient(
                circle at 15% 5%,
                rgba(99,102,241,0.13),
                transparent 28%
            ),
            radial-gradient(
                circle at 90% 15%,
                rgba(6,182,212,0.09),
                transparent 28%
            ),
            #070a11;
    }

    .block-container {
        max-width: 1200px;
        padding-top: 35px;
        padding-bottom: 50px;
    }

    /* =========================
       SIDEBAR
       ========================= */

    section[data-testid="stSidebar"] {
        background: #0b0f18;
        border-right: 1px solid #202838;
    }

    section[data-testid="stSidebar"] .block-container {
        padding-top: 25px;
    }

    /* =========================
       HERO
       ========================= */

    .hero-wrapper {
        padding: 10px 0 35px 0;
    }

    .hero {
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .hero-icon {
        width: 58px;
        height: 58px;
        border-radius: 17px;

        display: flex;
        align-items: center;
        justify-content: center;

        background:
            linear-gradient(
                135deg,
                #6366f1,
                #06b6d4
            );

        font-size: 30px;

        box-shadow:
            0 10px 35px
            rgba(99,102,241,0.28);
    }

    .hero-title {
        font-size: 40px;
        font-weight: 800;
        line-height: 1;
        letter-spacing: -1.5px;
        color: #f8fafc;
    }

    .hero-subtitle {
        margin-top: 9px;
        color: #94a3b8;
        font-size: 14px;
    }

    /* =========================
       CARDS
       ========================= */

    .glass-card {
        background: rgba(15,23,42,0.72);
        border: 1px solid #263244;
        border-radius: 18px;
        padding: 23px;
        margin-bottom: 18px;
        box-shadow:
            0 15px 40px
            rgba(0,0,0,0.20);
    }

    .card-heading {
        color: #f8fafc;
        font-size: 18px;
        font-weight: 750;
        margin-bottom: 5px;
    }

    .card-description {
        color: #94a3b8;
        font-size: 13px;
        line-height: 1.6;
        margin-bottom: 18px;
    }

    /* =========================
       METRICS
       ========================= */

    .metric {
        background: #0d1421;
        border: 1px solid #263449;
        border-radius: 16px;
        padding: 20px;
        min-height: 110px;
    }

    .metric-label {
        color: #7f8da3;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .metric-value {
        color: #f8fafc;
        font-size: 25px;
        font-weight: 800;
        margin-top: 8px;
    }

    /* =========================
       RED FLAGS
       ========================= */

    .red-flag {
        background: #0d1421;
        border: 1px solid #273449;
        border-radius: 12px;
        padding: 12px 14px;
        margin-bottom: 9px;
        color: #dbe4f0;
        font-size: 13px;
        line-height: 1.5;
    }

    /* =========================
       INFO
       ========================= */

    .recommendation {
        background: rgba(59,130,246,0.08);
        border: 1px solid rgba(59,130,246,0.25);
        border-radius: 13px;
        padding: 16px;
        color: #dbeafe;
        font-size: 14px;
        line-height: 1.6;
    }

    /* =========================
       SIDEBAR BRAND
       ========================= */

    .sidebar-brand {
        padding-bottom: 20px;
    }

    .sidebar-title {
        color: #f8fafc;
        font-size: 22px;
        font-weight: 800;
    }

    .sidebar-subtitle {
        color: #64748b;
        font-size: 12px;
        margin-top: 4px;
    }

    .sidebar-section {
        color: #94a3b8;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 22px;
        margin-bottom: 10px;
    }

    /* =========================
       FOOTER
       ========================= */

    .footer {
        text-align: center;
        color: #566277;
        font-size: 12px;
        padding: 35px 0 10px;
        line-height: 1.7;
    }

    /* =========================
       BUTTONS
       ========================= */

    .stButton > button {
        border-radius: 11px;
        border: 1px solid #313d52;
        background: #111827;
        color: #e5e7eb;
        font-weight: 700;
        min-height: 42px;
        transition: all 0.2s ease;
    }

    .stButton > button:hover {
        border-color: #6366f1;
        color: white;
        background: #161d2d;
    }

    /* =========================
       TEXT INPUT
       ========================= */

    input,
    textarea {
        background-color: #0b1220 !important;
        color: #f8fafc !important;
    }

    /* =========================
       TABS
       ========================= */

    button[data-baseweb="tab"] {
        font-weight: 700;
        font-size: 14px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SESSION STATE
# ============================================================

if "analysis" not in st.session_state:
    st.session_state.analysis = None


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">

            <div class="sidebar-title">
                🛡️ SentinelAI
            </div>

            <div class="sidebar-subtitle">
                Scam & Phishing Intelligence
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sidebar-section">AI Configuration</div>',
        unsafe_allow_html=True
    )

    api_key = st.text_input(
        "Groq API Key",
        type="password",
        placeholder="gsk_...",
        help="Used only during this session."
    )

    model = st.selectbox(
        "AI Model",
        [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant"
        ]
    )

    st.markdown(
        '<div class="sidebar-section">Detection Signals</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        🚨 Urgency & pressure<br>
        🔗 Suspicious URLs<br>
        🔐 Credential requests<br>
        💰 Financial manipulation<br>
        🎁 Fake rewards<br>
        👤 Impersonation<br>
        📱 Social engineering
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="sidebar-section">Privacy</div>',
        unsafe_allow_html=True
    )

    st.info(
        "Do not enter real passwords, OTPs, "
        "credit-card numbers, or other sensitive "
        "information."
    )


# ============================================================
# HERO
# ============================================================

st.markdown(
    """
    <div class="hero-wrapper">

        <div class="hero">

            <div class="hero-icon">
                🛡️
            </div>

            <div>

                <div class="hero-title">
                    SentinelAI
                </div>

                <div class="hero-subtitle">
                    Intelligent scam and phishing detection
                    powered by Generative AI
                </div>

            </div>

        </div>

    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# TABS
# ============================================================

message_tab, url_tab = st.tabs(
    [
        "💬 Message Scanner",
        "🔗 URL Scanner"
    ]
)


# ============================================================
# MESSAGE TAB
# ============================================================

with message_tab:

    st.markdown(
        """
        <div class="glass-card">

            <div class="card-heading">
                🔍 Analyze a suspicious message
            </div>

            <div class="card-description">
                Analyze SMS messages, emails, WhatsApp messages,
                job offers, banking alerts, social-media messages,
                and other suspicious content.
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    message = st.text_area(
        "Suspicious message",
        height=220,
        placeholder=(
            "Paste the suspicious message here..."
        ),
        label_visibility="collapsed"
    )

    col1, col2, col3 = st.columns(
        [1.2, 1.0, 3.0]
    )

    with col1:

        analyze_message = st.button(
            "🔍 Analyze Message",
            key="message_analyze"
        )

    with col2:

        clear_message = st.button(
            "↻ Clear",
            key="message_clear"
        )

    if clear_message:

        st.session_state.analysis = None
        st.rerun()

    if analyze_message:

        if not message.strip():

            st.warning(
                "Please paste a message first."
            )

        elif not api_key:

            st.warning(
                "Enter your Groq API key in the sidebar."
            )

        else:

            with st.spinner(
                "🧠 SentinelAI is analyzing the message..."
            ):

                result = analyze_with_groq(
                    api_key,
                    model,
                    message,
                    "message"
                )

                if result:

                    st.session_state.analysis = result


# ============================================================
# URL TAB
# ============================================================

with url_tab:

    st.markdown(
        """
        <div class="glass-card">

            <div class="card-heading">
                🔗 Analyze a suspicious URL
            </div>

            <div class="card-description">
                Inspect the structure of a URL and use AI
                to identify possible phishing indicators.
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    url = st.text_input(
        "Suspicious URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed"
    )

    col1, col2, col3 = st.columns(
        [1.2, 1.0, 3.0]
    )

    with col1:

        analyze_url = st.button(
            "🔗 Analyze URL",
            key="url_analyze"
        )

    with col2:

        clear_url = st.button(
            "↻ Clear",
            key="url_clear"
        )

    if clear_url:

        st.session_state.analysis = None
        st.rerun()

    if analyze_url:

        if not url.strip():

            st.warning(
                "Please enter a URL first."
            )

        elif not api_key:

            st.warning(
                "Enter your Groq API key in the sidebar."
            )

        else:

            url_info = inspect_url(url)

            with st.spinner(
                "🧠 SentinelAI is analyzing the URL..."
            ):

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
# RESULTS
# ============================================================

if st.session_state.analysis:

    result = st.session_state.analysis

    st.markdown("---")

    st.markdown(
        """
        <div style="margin:25px 0 18px;">

            <div style="
                font-size:26px;
                font-weight:800;
                color:#f8fafc;
            ">
                📊 Security Analysis
            </div>

            <div style="
                color:#64748b;
                font-size:13px;
                margin-top:5px;
            ">
                AI-generated assessment of the submitted content.
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    risk = str(
        result.get(
            "risk_level",
            "LOW"
        )
    ).upper()

    try:

        score = int(
            result.get(
                "risk_score",
                0
            )
        )

    except Exception:

        score = 0

    score = max(
        0,
        min(100, score)
    )

    category = result.get(
        "category",
        "Other"
    )

    summary = result.get(
        "summary",
        "No explanation available."
    )

    recommendation = result.get(
        "recommendation",
        "Verify the information through a trusted official channel."
    )

    if risk == "HIGH":

        risk_icon = "🔴"
        risk_text = "HIGH RISK"

    elif risk == "MEDIUM":

        risk_icon = "🟠"
        risk_text = "MEDIUM RISK"

    else:

        risk_icon = "🟢"
        risk_text = "LOW RISK"


    # ========================================================
    # METRICS
    # ========================================================

    c1, c2, c3 = st.columns(3)

    with c1:

        st.markdown(
            f"""
            <div class="metric">

                <div class="metric-label">
                    Risk Level
                </div>

                <div class="metric-value">
                    {risk_icon} {risk}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:

        st.markdown(
            f"""
            <div class="metric">

                <div class="metric-label">
                    Risk Score
                </div>

                <div class="metric-value">
                    {score}/100
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:

        st.markdown(
            f"""
            <div class="metric">

                <div class="metric-label">
                    Category
                </div>

                <div class="metric-value"
                     style="font-size:21px;">

                    {category}

                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    st.markdown("<br>", unsafe_allow_html=True)


    # ========================================================
    # RISK CARD
    # ========================================================

    st.markdown(
        f"""
        <div class="glass-card">

            <div style="
                display:flex;
                justify-content:space-between;
                align-items:center;
            ">

                <div>

                    <div style="
                        color:#f8fafc;
                        font-size:28px;
                        font-weight:800;
                    ">
                        {risk_icon} {risk_text}
                    </div>

                    <div style="
                        color:#64748b;
                        margin-top:5px;
                        font-size:13px;
                    ">
                        AI assessment score
                    </div>

                </div>

                <div style="
                    font-size:32px;
                    font-weight:800;
                    color:#f8fafc;
                ">
                    {score}
                </div>

            </div>

        </div>
        """,
        unsafe_allow_html=True
    )

    # Progress bar

    st.progress(
        score / 100,
        text=f"Risk score: {score}/100"
    )


    st.markdown("<br>", unsafe_allow_html=True)


    # ========================================================
    # DETAILS
    # ========================================================

    left, right = st.columns(2)

    with left:

        st.markdown(
            """
            <div class="glass-card">

                <div class="card-heading">
                    🚩 Detected Red Flags
                </div>

                <div class="card-description">
                    Suspicious indicators identified by SentinelAI.
                </div>

            """,
            unsafe_allow_html=True
        )

        flags = result.get(
            "red_flags",
            []
        )

        if isinstance(flags, str):

            flags = [flags]

        if not flags:

            flags = [
                "No specific red flags identified."
            ]

        for flag in flags:

            st.markdown(
                f"""
                <div class="red-flag">
                    ⚠️ &nbsp; {flag}
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown(
            "</div>",
            unsafe_allow_html=True
        )


    with right:

        st.markdown(
            f"""
            <div class="glass-card">

                <div class="card-heading">
                    🧠 AI Explanation
                </div>

                <div class="card-description">
                    Why the content received this assessment.
                </div>

                <div style="
                    color:#cbd5e1;
                    font-size:14px;
                    line-height:1.8;
                ">
                    {summary}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # RECOMMENDATION
    # ========================================================

    st.markdown(
        f"""
        <div class="glass-card">

            <div class="card-heading">
                🛡️ Recommended Action
            </div>

            <div class="card-description">
                Suggested safety steps based on the analysis.
            </div>

            <div class="recommendation">
                <b>Safety recommendation</b><br><br>
                {recommendation}
            </div>

        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">

        🛡️ <b>SentinelAI</b>
        &nbsp;•&nbsp;
        AI Scam & Phishing Detector

        <br>

        AI analysis may occasionally be incorrect.
        Always verify suspicious communications
        through trusted official channels.

    </div>
    """,
    unsafe_allow_html=True
)
