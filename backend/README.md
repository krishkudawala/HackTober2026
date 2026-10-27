# KavachX Bharat — Backend API

FastAPI backend service for **KavachX Bharat** (AI-powered scam detection and digital safety application for Bharat).

---

## 🏗️ Project Architecture

```
backend/
├── app/
│   ├── __init__.py           # Application package definition
│   ├── main.py               # FastAPI application entry point, CORS, lifespan & health
│   ├── api/
│   │   ├── __init__.py       # Router exports
│   │   └── routes.py         # REST endpoints (POST /api/analyze/message)
│   ├── ai/
│   │   ├── __init__.py       # AI package exports
│   │   ├── engine.py         # Normalization, language detection & provider orchestrator
│   │   ├── fallback_classifier.py # Deterministic rule-based analysis & localized guidance
│   │   └── llm_provider.py   # Configurable provider manager (fallback, LiteRT-LM, Ollama)
│   ├── models/
│   │   ├── __init__.py       # Schema exports
│   │   └── schemas.py        # Pydantic request and response schemas (1:1 with Flutter client)
│   ├── scoring/
│   │   ├── __init__.py       # Scoring exports
│   │   └── risk_engine.py    # Deterministic signal detection & 0–100 risk scoring
│   └── core/
│       ├── __init__.py       # Core package definition
│       └── config.py         # Application settings & environment configuration
├── tests/
│   ├── __init__.py           # Tests package definition
│   ├── test_health.py        # Health and root endpoint verification
│   └── test_analysis.py      # Contract, scoring, validation, and multilingual tests
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
└── README.md                 # Backend documentation
```

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.10+ (tested with Python 3.15)
- pip / virtualenv

### 2. Install Dependencies

From the `backend/` directory:

```bash
python -m pip install -r requirements.txt
```

### 3. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Key environment options in `.env`:
- `AI_PROVIDER`: `fallback` (default rules-only), `litert` (Gemma 4 E4B Instruct via LiteRT-LM), or `ollama`.
- `LITERT_MODEL_PATH`: Optional path to local `.litertlm` model file.
- `OLLAMA_BASE_URL`: Base URL for local Ollama service (default: `http://localhost:11434`).
- `OLLAMA_MODEL`: Model tag for Ollama (default: `qwen2.5:1.5b`).

### 4. Run the Development Server

From the `backend/` directory:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server starts on `http://127.0.0.1:8000`.

---

## 📡 API Endpoints

### 1. Health Check

- **URL:** `GET /health`
- **Authentication:** None (Hackathon MVP)
- **Response Format:**

```json
{
  "status": "ok",
  "service": "KavachX Bharat API",
  "version": "1.0.0"
}
```

---

### 2. Message Analysis (Milestone B02)

- **URL:** `POST /api/analyze/message`
- **Summary:** Analyze text communication (SMS, WhatsApp, call transcript, or plain text) for fraud patterns.
- **Content-Type:** `application/json`

#### Request Schema

```json
{
  "message": "Required string (1 to 5000 characters)",
  "input_type": "sms | whatsapp | call_transcript | audio | text (default: text)",
  "source_info": "Optional string (e.g. sender phone number or handle)",
  "language": "Optional string: en | hi | pa | hinglish | auto (default: en)"
}
```

#### Language Support

| Code | Language | Script / Handling |
|---|---|---|
| `en` | English | Default plain-language analysis |
| `hi` | Hindi | Devanagari script responses & safety guidance |
| `pa` | Punjabi | Gurmukhi script & Roman Punjabi phrases |
| `hinglish`| Hinglish | Conversational Hindi in Latin script |
| `auto` | Auto-Detect | Inferred automatically from text script and vocabulary |

#### Risk Scoring Policy & Thresholds

Scores range deterministically from `0` to `100`:

| Risk Score | Risk Level | Description & Action |
|---|---|---|
| **0 – 29** | `SAFE` | No significant fraud indicators; legitimate notifications |
| **30 – 64** | `VERIFY` | Suspicious signals detected; requires manual verification before action |
| **65 – 100** | `HIGH_RISK` | Severe fraud indicators (digital arrest threats, credential theft, malicious URLs) |

#### Supported Scam Categories

- **Phishing**: Fake banking links, verification portals, credential harvesting.
- **Fake Bank Support**: Impersonating customer support claiming account/card blocked, demanding OTP.
- **Digital Arrest Scam**: Impersonating police, CBI, ED, or customs threatening video arrest or warrants.
- **UPI / Payment Scam**: Reverse PIN deception, fake collect requests, QR code cashback tricks.
- **Investment Scam**: Unrealistic guaranteed returns, crypto trading groups, zero risk claims.
- **Prepaid Task / Job Scam**: Upfront registration fees for rating or review tasks.
- **Lottery / Prize Scam**: Unsolicited lottery or lucky draw winnings demanding processing fees.
- **Government / Authority Impersonation**: Impersonating ministries, electricity bill disconnection threats.
- **Legitimate**: Normal personal, business, delivery tracking, or standard bank transaction alerts.
- **Unknown Scam Type**: Unclassified or novel suspicious pattern.

#### Example Request (cURL)

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/message" \
     -H "Content-Type: application/json" \
     -d '{
       "message": "Your SBI account will be blocked today due to pending KYC. Click http://sbi-kyc-verify.online to update immediately.",
       "input_type": "sms",
       "language": "en"
     }'
```

#### Example Successful Response

```json
{
  "id": "7f3b8e21-0a42-4f8b-9d1a-5b1234567890",
  "scam_type": "Phishing",
  "risk_score": 65,
  "risk_level": "HIGH_RISK",
  "confidence": 0.9,
  "summary": "KavachX Bharat has classified this communication as a potential Phishing with a risk score of 65/100 (HIGH_RISK).",
  "explanation": "HIGH RISK: This communication contains suspicious links designed to harvest sensitive personal or banking credentials. The URLs mimic official institutions to deceive users into submitting passwords or downloading malicious files.",
  "red_flags": [
    {
      "indicator": "Suspicious URL",
      "description": "Directs to unverified, shortened, or spoofed web link.",
      "severity": "critical"
    },
    {
      "indicator": "Credential Theft Pretext",
      "description": "Fake portal designed to steal login credentials or banking info.",
      "severity": "critical"
    }
  ],
  "recommended_actions": [
    "Do NOT click on unverified links or download APK files from SMS/WhatsApp.",
    "Verify the website address carefully — scam domains mimic official brand names.",
    "Report phishing links to cybercrime.gov.in and 1930."
  ],
  "detected_entities": [
    "Confirmed Malicious URL",
    "Bank / KYC Impersonation"
  ],
  "score_breakdown": [
    {
      "signal": "Confirmed Malicious URL",
      "points": 40,
      "description": "The message contains a confirmed malicious, phishing, or spoofed URL."
    },
    {
      "signal": "Bank / KYC Impersonation",
      "points": 20,
      "description": "The message impersonates a bank or threatens account suspension regarding KYC."
    },
    {
      "signal": "Generic Urgency Language",
      "points": 5,
      "description": "The message creates artificial urgency."
    }
  ],
  "input_type": "sms",
  "input_text": "Your SBI account will be blocked today due to pending KYC. Click http://sbi-kyc-verify.online to update immediately.",
  "ai_provider": "fallback",
  "verdict": "likely_scam",
  "evidence": [
    "Confirmed Malicious URL (40 pts): The message contains a confirmed malicious, phishing, or spoofed URL.",
    "Bank / KYC Impersonation (20 pts): The message impersonates a bank or threatens account suspension regarding KYC."
  ],
  "model_name": "rule_engine",
  "language": "en",
  "fallback_used": true,
  "fallback_reason": null,
  "signals": [
    "Confirmed Malicious URL",
    "Bank / KYC Impersonation",
    "Generic Urgency Language"
  ],
  "analysis_mode": "rules-only",
  "analysis_complete": true,
  "warnings": [
    "Deterministic rule-based analysis engine used."
  ],
  "created_at": "2026-10-27T12:00:00.000000+00:00",
  "disclaimer": "AI-generated risk assessment. Verify critical decisions through official channels."
}
```

---

### 3. Interactive Documentation

- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

---

## 📱 Frontend Integration (Flutter / Android)

When integrating the Flutter mobile app with this backend, configure the base URL according to the execution context:

| Environment | Base URL | Notes |
|---|---|---|
| **Host Computer (Desktop / Web)** | `http://127.0.0.1:8000` | Local development on same machine |
| **Android Emulator** | `http://10.0.2.2:8000` | Android emulator loopback to host |
| **Physical Android Device** | `http://<LAN_IP>:8000` | Requires phone & PC on same Wi-Fi with firewall port 8000 open |

---

## 🧪 Automated Testing

Run the full pytest suite from the `backend/` directory:

```bash
python -m pytest tests/ -v
```
