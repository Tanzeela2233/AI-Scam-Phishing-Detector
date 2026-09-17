# 🛡️ SentinelAI — AI Scam & Phishing Detector

> 🔐 An intelligent GenAI-powered security tool that analyzes suspicious messages and URLs and identifies potential scam and phishing threats.

## ✨ Features

- 💬 **Message Scanner** — Analyze SMS, emails, WhatsApp messages, job offers, and more.
- 🔗 **URL Scanner** — Inspect suspicious URLs and identify potential phishing indicators.
- 🤖 **GenAI Analysis** — AI explains why content may be suspicious.
- 🚨 **Risk Detection** — Low, Medium, and High risk classification.
- 📊 **Risk Score** — Get an easy-to-understand score from 0–100.
- 🚩 **Red Flag Detection** — Identifies urgency, fake rewards, credential requests, suspicious links, and social engineering.
- 🛡️ **Safety Recommendations** — Provides practical actions to stay safe.
- 🎨 **Professional Dark UI** — Clean cybersecurity dashboard built with Streamlit.

---

## 🧠 How It Works

```text
       👤 User
          │
          ▼
   💬 Message / 🔗 URL
          │
          ▼
     🤖 GenAI Model
          │
          ▼
   🔍 Threat Analysis
          │
     ┌────┴────┐
     ▼         ▼
 🚨 Risk    🚩 Red Flags
     │         │
     └────┬────┘
          ▼
   🛡️ Safety Advice

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| 🐍 Python | Core application |
| 🎨 Streamlit | Web interface |
| 🤖 Groq API | GenAI inference |
| 🧠 OpenAI GPT-OSS 20B | AI analysis |
| 🧠 OpenAI GPT-OSS 120B | AI analysis |
| 🌐 URL Parsing | URL inspection |
| 📡 Requests | API communication |
| ☁️ Streamlit Cloud | Deployment |
