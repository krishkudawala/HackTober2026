# KavachX Bharat 🛡️

**AI-powered scam detection and digital safety for Bharat — built to make online fraud easier to recognize, understand, and avoid.**

## 📌 About the Project

KavachX Bharat is an AI-powered mobile application designed to help users identify potential online scams, phishing attempts, and fraudulent messages. It aims to make digital safety accessible to everyone, especially elderly people, first-time smartphone users, and people who may find technical security warnings difficult to understand.

The application analyzes suspicious messages and provides easy-to-understand risk assessments, explanations of potential red flags, and actionable safety recommendations. With a focus on accessibility, KavachX Bharat aims to communicate security insights in simple language, with support for regional languages such as Hindi and Punjabi.

By combining on-device AI capabilities, backend-based analysis, and rule-based detection, the project explores a practical, multi-layered approach to making digital communication safer.

## 🧠 Technology Stack

| Component | Technologies |
|---|---|
| Mobile application | Flutter, Dart |
| Native Android integration | Kotlin |
| AI model | Google Gemma 4 E4B |
| On-device inference | LiteRT-LM |
| Backend API | Python, FastAPI |
| AI inference architecture | On-device and backend-based inference |
| Detection fallback | Rule-based analysis |

## ⚙️ How It Works

1. **Input:** The user submits a suspicious message for analysis, or a supported notification-analysis workflow detects a potentially risky message.
2. **Analysis:** The application uses the configured detection pipeline, which may include on-device Gemma inference, backend AI analysis, or rule-based fallback.
3. **Risk Assessment:** The system evaluates potential scam indicators and generates a risk classification.
4. **Explanation:** The application presents the result with understandable reasons and relevant warning signs.
5. **Safety Recommendations:** The user receives guidance on what to do next and how to avoid potential financial or personal-data loss.

## 🎯 Problem Statement

Digital fraud increasingly targets people through fake KYC updates, fraudulent payment notifications, phishing links, impersonation attempts, fake job offers, and other deceptive messages.

Many existing security tools provide warnings that can be difficult for non-technical users to understand. KavachX Bharat aims to bridge this gap by combining AI-assisted detection with clear explanations and accessible safety guidance.

## 🌍 Vision

To make digital safety more accessible across India by helping people recognize suspicious communications before they become victims of online fraud.

---

**KavachX Bharat — Making digital safety understandable for everyone.** 🛡️
