# KavachX Bharat — Backend API

FastAPI backend service for **KavachX Bharat** (AI-powered scam detection and digital safety application for Bharat).

---

## 🏗️ Project Architecture

```
backend/
├── app/
│   ├── __init__.py           # Application package definition
│   ├── main.py               # FastAPI entry point, CORS, lifespan & health
│   ├── api/
│   │   ├── __init__.py       # Router exports
│   │   └── routes.py         # REST endpoints (message, transcript, audio)
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
│   ├── services/
│   │   ├── __init__.py       # Services package exports
│   │   └── stt_service.py    # Speech-to-Text service abstraction with demo mode
│   └── core/
│       ├── __init__.py       # Core package definition
│       └── config.py         # Application settings & environment configuration
├── tests/
│   ├── __init__.py           # Tests package definition
│   ├── test_health.py        # Health and root endpoint verification
│   ├── test_analysis.py      # Message contract, scoring, and multilingual tests (B02)
│   └── test_transcript_audio.py # Call transcript and audio upload tests (B03)
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
- `STT_PROVIDER`: `demo` (default: transparent demo fallback, zero credentials required) or custom provider.
- `MAX_AUDIO_UPLOAD_BYTES`: Maximum audio upload size in bytes (default: `26214400` = 25 MB).

### 4. Run the Development Server

From the `backend/` directory:

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
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
- **Summary:** Analyze text communication (SMS, WhatsApp, plain text) for fraud patterns.
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

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/message" \
     -H "Content-Type: application/json" \
     -d '{
       "message": "Your SBI account will be blocked today due to pending KYC. Click http://sbi-kyc-verify.online to update immediately.",
       "input_type": "sms",
       "language": "en"
     }'
```

---

### 3. Call Transcript Analysis (Milestone B03)

- **URL:** `POST /api/analyze/transcript`
- **Summary:** Analyze a call transcript for digital arrest, impersonation, or coercion patterns.
- **Content-Type:** `application/json`
- **Pipeline:** Reuses the shared normalization, language resolution, classification, and scoring pipeline.
- **Contract:** Returns the exact same `AnalysisResult` response contract as `POST /api/analyze/message`, setting `input_type="call_transcript"` and preserving the transcript in `input_text`.

#### Request Schema

```json
{
  "transcript": "Required string (1 to 10000 characters)",
  "source_info": "Optional string (e.g. caller phone number or telecom provider)",
  "language": "Optional string: en | hi | pa | hinglish | auto (default: en)"
}
```

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/transcript" \
     -H "Content-Type: application/json" \
     -d '{
       "transcript": "Caller: I am Senior Inspector Sharma from Mumbai Police Crime Branch. Your Aadhaar card is linked to money laundering. You are under digital arrest. Transfer Rs 50,000 to the verification account right now.",
       "source_info": "+91-9876543210",
       "language": "en"
     }'
```

---

### 4. Audio Upload Analysis (Milestone B03)

- **URL:** `POST /api/analyze/audio`
- **Summary:** Upload audio recordings (e.g. WAV, MP3, M4A) for Speech-to-Text transcription followed by scam analysis.
- **Content-Type:** `multipart/form-data`
- **Upload Size Limit:** 25 MB max (enforced with HTTP 413 error if exceeded).
- **STT Provider & Demo Mode:**
  - By default (`STT_PROVIDER=demo`), the service returns a transparent demo-mode response prompting manual transcript entry. No fake transcripts or fabricated analyses are produced.
  - When an STT provider is configured and successfully transcribes audio, the transcript is routed through the shared analysis engine with `input_type="audio"`.

#### Request Parameters (Multipart Form)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `file` | Binary File | Yes | Audio file (WAV, MP3, M4A, etc.) up to 25 MB |
| `language` | Form String | No | Language code hint (`en`, `hi`, `pa`, `hinglish`, `auto`; default: `en`) |

#### Demo-Mode Response (`STT_PROVIDER=demo`)

```json
{
  "status": "demo_mode",
  "message": "Speech-to-Text is in demo mode. Please paste the call transcript manually into the transcript analysis tool or configure an STT provider.",
  "provider": "demo",
  "transcript": "",
  "analysis": null
}
```

#### Successful Transcription Response

```json
{
  "status": "success",
  "message": null,
  "provider": "stt",
  "transcript": "Caller: You are under digital arrest. Transfer money immediately.",
  "analysis": {
    "id": "c4b78912-3456-4abc-9def-123456789abc",
    "scam_type": "Digital Arrest Scam",
    "risk_score": 75,
    "risk_level": "HIGH_RISK",
    "confidence": 0.9,
    "summary": "KavachX Bharat has classified this communication as a potential Digital Arrest Scam with a risk score of 75/100 (HIGH_RISK).",
    "explanation": "HIGH RISK: This communication impersonates law-enforcement officials and threatens immediate arrest...",
    "red_flags": [
      {
        "indicator": "Digital Arrest Coercion",
        "description": "Threatens immediate arrest via video call or telephone.",
        "severity": "critical"
      }
    ],
    "recommended_actions": [
      "No Indian law enforcement agency or court conducts arrests over telephone or video calls.",
      "Do NOT transfer any money or disclose your bank account details.",
      "Report the call immediately to the National Cyber Crime Helpline at 1930."
    ],
    "detected_entities": ["Government / Law Enforcement Impersonation", "Arrest / Legal Threat"],
    "score_breakdown": [
      {
        "signal": "Government / Law Enforcement Impersonation",
        "points": 25,
        "description": "The message impersonates a government or law-enforcement authority."
      },
      {
        "signal": "Arrest / Legal Threat",
        "points": 25,
        "description": "The message threatens arrest or legal prosecution to create fear."
      }
    ],
    "input_type": "audio",
    "input_text": "Caller: You are under digital arrest. Transfer money immediately.",
    "ai_provider": "fallback",
    "verdict": "likely_scam",
    "evidence": ["Government / Law Enforcement Impersonation (25 pts)..."],
    "model_name": "rule_engine",
    "language": "en",
    "fallback_used": true,
    "fallback_reason": null,
    "signals": ["Government / Law Enforcement Impersonation", "Arrest / Legal Threat"],
    "analysis_mode": "rules-only",
    "analysis_complete": true,
    "warnings": ["Deterministic rule-based analysis engine used."],
    "created_at": "2026-10-27T12:00:00.000000+00:00",
    "disclaimer": "AI-generated risk assessment. Verify critical decisions through official channels."
  }
}
```

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/audio" \
     -F "file=@call_recording.wav;type=audio/wav" \
     -F "language=en"
```

---

## 🛡️ Risk Scoring Policy & Thresholds

| Risk Score | Risk Level | Description & Action |
|---|---|---|
| **0 – 29** | `SAFE` | No significant fraud indicators; legitimate notifications |
| **30 – 64** | `VERIFY` | Suspicious signals detected; requires manual verification before action |
| **65 – 100** | `HIGH_RISK` | Severe fraud indicators (digital arrest threats, credential theft, malicious URLs) |

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
