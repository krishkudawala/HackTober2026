# KavachX Bharat — Backend API

FastAPI backend service for **KavachX Bharat** (AI-powered scam detection and digital safety application for Bharat).

---

## 🏗️ Project Architecture

```
backend/
├── app/
│   ├── __init__.py           # Application package definition
│   ├── main.py               # FastAPI application entry point & health endpoint
│   ├── api/
│   │   ├── __init__.py       # API router package export
│   │   └── routes.py         # Top-level API router (ready for B02: POST /api/analyze/message)
│   └── core/
│       ├── __init__.py       # Core package definition
│       └── config.py         # Application settings & environment variables
├── tests/
│   ├── __init__.py           # Tests package definition
│   └── test_health.py        # Automated tests for /health and core endpoints
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

### 4. Run the Development Server

From the `backend/` directory, run:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will start on port `8000`.

---

## 📡 Endpoints

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

### 2. Interactive API Documentation

- **Swagger UI:** `http://127.0.0.1:8000/docs`
- **ReDoc:** `http://127.0.0.1:8000/redoc`

### 3. Scam Analysis Endpoint (Prepared for B02)

- **URL:** `POST /api/analyze/message`
- *Note: Router mounted under `/api` in `app/api/routes.py`, schema and inference logic will be integrated in milestone B02.*

---

## 📱 Frontend Integration (Flutter / Android)

When integrating the Flutter mobile app with this backend, use the appropriate base URL:

| Environment | Base URL |
|---|---|
| **Same Computer (Browser / Desktop)** | `http://127.0.0.1:8000` |
| **Android Emulator (connecting to host)** | `http://10.0.2.2:8000` |
| **Physical Android Device** | `http://<YOUR_LAN_IP>:8000` *(devices must be on the same Wi-Fi/network and firewall must permit port 8000)* |

*Note: Avoid hardcoding temporary local IP addresses into source control.*

---

## 🧪 Testing

Run automated tests using pytest:

```bash
python -m pytest tests/ -v
```
