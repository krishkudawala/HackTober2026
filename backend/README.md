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
│   │   └── routes.py         # REST endpoints (message, transcript, audio, scans, reports, stats, demo)
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
│   │   ├── stt_service.py    # Speech-to-Text service abstraction with demo mode (B03)
│   │   ├── scan_store.py     # In-memory persistence for scans, reports & stats (B04)
│   │   └── demo_scenarios.py # Preset evaluation scenarios (B04)
│   └── core/
│       ├── __init__.py       # Core package definition
│       └── config.py         # Application settings & environment configuration
├── tests/
│   ├── __init__.py           # Tests package definition
│   ├── test_health.py        # Health and root endpoint verification
│   ├── test_analysis.py      # Message contract, scoring, and multilingual tests (B02)
│   ├── test_transcript_audio.py # Call transcript and audio upload tests (B03)
│   └── test_scans_reports_stats.py # Scan history, reports, stats, and demo runner tests (B04)
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
- **Summary:** Analyze text communication (SMS, WhatsApp, plain text) for fraud patterns. Persists the result into the scan store.
- **Content-Type:** `application/json`

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
- **Summary:** Analyze a call transcript for digital arrest, impersonation, or coercion patterns. Persists the result into the scan store.
- **Content-Type:** `application/json`

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/transcript" \
     -H "Content-Type: application/json" \
     -d '{
       "transcript": "Caller: I am Senior Inspector Sharma from Mumbai Police Crime Branch. Your Aadhaar is linked to money laundering. You are under digital arrest. Transfer Rs 50,000 to the verification account right now.",
       "source_info": "+91-9876543210",
       "language": "en"
     }'
```

---

### 4. Audio Upload Analysis (Milestone B03)

- **URL:** `POST /api/analyze/audio`
- **Summary:** Upload audio recordings (e.g. WAV, MP3, M4A) for Speech-to-Text transcription followed by scam analysis.
- **Content-Type:** `multipart/form-data`
- **Upload Size Limit:** 25 MB max (enforced with HTTP 413 if exceeded).

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/audio" \
     -F "file=@call_recording.wav;type=audio/wav" \
     -F "language=en"
```

---

### 5. Scan History (Milestone B04)

- **URL:** `GET /api/scans`
- **Summary:** Retrieve scan summaries sorted newest first.
- **Storage:** In-memory scan store (retained for backend process lifetime).

#### Example cURL

```bash
curl -X GET "http://127.0.0.1:8000/api/scans"
```

#### Example Response

```json
[
  {
    "id": "7f3b8e21-0a42-4f8b-9d1a-5b1234567890",
    "scam_type": "Phishing",
    "risk_score": 65,
    "risk_level": "HIGH_RISK",
    "input_type": "sms",
    "summary": "KavachX Bharat has classified this communication as a potential Phishing with a risk score of 65/100 (HIGH_RISK).",
    "created_at": "2026-10-27T12:00:00.000000+00:00"
  }
]
```

---

### 6. Single Scan Retrieval (Milestone B04)

- **URL:** `GET /api/scans/{scan_id}`
- **Summary:** Retrieve full analysis details for a specific scan ID. Returns HTTP 404 if not found.

#### Example cURL

```bash
curl -X GET "http://127.0.0.1:8000/api/scans/7f3b8e21-0a42-4f8b-9d1a-5b1234567890"
```

---

### 7. Incident Reporting (Milestone B04)

- **URL:** `POST /api/reports`
- **Summary:** Record an incident report linked to a valid existing scan record.
- **Validation:** Validates that `scan_id` exists (returns HTTP 404 if not found) and ensures `risk_score` is within `0–100`.
- **Note:** Reports are stored internally in the backend for incident tracking; for legal complaints, users are referred to the National Cyber Crime Helpline at 1930.

#### Example cURL

```bash
curl -X POST "http://127.0.0.1:8000/api/reports" \
     -H "Content-Type: application/json" \
     -d '{
       "scan_id": "7f3b8e21-0a42-4f8b-9d1a-5b1234567890",
       "scam_type": "Phishing",
       "risk_score": 65,
       "description": "Received fake SBI KYC SMS with phishing link.",
       "communication_source": "+91-9876543210"
     }'
```

#### Example Response

```json
{
  "id": "e81d432e-b6a9-4a3f-8c12-998877665544",
  "status": "recorded",
  "message": "Incident report recorded in KavachX Bharat backend. For immediate assistance, contact the National Cyber Crime Helpline at 1930.",
  "scan_id": "7f3b8e21-0a42-4f8b-9d1a-5b1234567890",
  "created_at": "2026-10-27T12:05:00.000000+00:00"
}
```

---

### 8. Dashboard Statistics (Milestone B04)

- **URL:** `GET /api/stats`
- **Summary:** Return aggregated fraud metrics derived from scan history.

#### Statistical Thresholds

- **Total Scans:** Count of all processed scans.
- **Threats Detected:** Scans with `risk_score >= 30` (includes `VERIFY` and `HIGH_RISK`).
- **High-Risk Alerts:** Scans with `risk_score >= 65` (`HIGH_RISK`).
- **Critical Alerts:** Scans with severe risk `risk_score >= 80` (digital arrest coercions, confirmed phishing APKs/IPs).
- **Protection Status:** `"active"`.

#### Example cURL

```bash
curl -X GET "http://127.0.0.1:8000/api/stats"
```

#### Example Response

```json
{
  "total_scans": 12,
  "threats_detected": 8,
  "high_risk_alerts": 5,
  "critical_alerts": 2,
  "protection_status": "active"
}
```

---

### 9. Preset Demo Scenarios (Milestone B04)

- **URL:** `GET /api/demo/scenarios`
  Returns the list of preset evaluation scenarios (digital arrest, fake bank support, investment scam, prepaid task scam, phishing, UPI scam, safe message).
- **URL:** `POST /api/demo/run/{scenario_id}`
  Executes the scenario through the shared analysis engine, records it as a scan, and returns the full analysis result. Returns HTTP 404 for unknown scenario IDs.

#### Example cURL

```bash
# List scenarios
curl -X GET "http://127.0.0.1:8000/api/demo/scenarios"

# Run a scenario
curl -X POST "http://127.0.0.1:8000/api/demo/run/demo_digital_arrest"
```

---

## 🔒 Storage Architecture & Privacy Policies

1. **In-Memory Storage:**
   The backend uses a clean service repository (`ScanStore`) retaining data for the lifetime of the backend process. This avoids paid cloud services, external database requirements, or heavy dependencies.
2. **Data Minimization & Privacy:**
   - Summary scan records contain only metadata (`id`, `scam_type`, `risk_score`, `risk_level`, `input_type`, `summary`, `created_at`).
   - Submitted message bodies, call transcripts, audio binaries, and user report descriptions are never written to disk logs or public monitoring feeds.

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
