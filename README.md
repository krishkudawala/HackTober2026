# 🛡️ KavachX Bharat
### Your AI-Powered Shield Against Digital Scams

**Making digital safety understandable, accessible, and actionable for every Indian.**

KavachX Bharat is an AI-powered mobile security application designed to help people identify potential digital scams before they become victims. It analyzes suspicious messages, explains warning signs in simple language, and recommends practical steps to stay safe.

Built with a focus on **accessible security, regional-language communication, and privacy-conscious AI**, KavachX Bharat aims to bridge the gap between increasingly sophisticated online fraud and the people most vulnerable to it.

> **Don't just detect the scam. Explain it. Empower the person. Prevent the loss.**

---

## 🚨 The Problem: Digital Fraud Is Also an Accessibility Problem

A suspicious message doesn't look suspicious to everyone.

A fake KYC expiry warning can look like an official bank notification. A fraudulent UPI refund can appear to be a legitimate payment. A fake job offer can exploit someone's search for employment. A message asking for an OTP may seem harmless until money disappears from an account.

The challenge isn't simply detecting malicious messages. It's helping people **understand why a message is dangerous and what they should do next**.

Many users—including elderly people, first-time smartphone users, and people with limited digital literacy—may struggle to recognize manipulation, urgency, impersonation, and phishing attempts.

For users more comfortable with Hindi or Punjabi than technical English, conventional security warnings can create another barrier.

### The gap KavachX Bharat addresses

- **Detection without understanding:** A warning is less useful if the user doesn't understand its meaning.
- **Language barriers:** Security guidance should be understandable to the people receiving it.
- **Reactive protection:** Users need help evaluating suspicious messages before acting on them.
- **Trust and privacy:** Security tools should carefully handle sensitive messages and avoid making unsupported claims.

## 💡 Our Solution

KavachX Bharat transforms suspicious messages into understandable, actionable security insights.

Users can submit a suspicious message for analysis. The application evaluates potential scam indicators and presents a risk assessment, an explanation of relevant warning signs, and recommendations for safer action.

Rather than treating security as a technical score alone, KavachX Bharat focuses on helping users answer three questions:

1. **Should I trust this message?**
2. **What makes it suspicious?**
3. **What should I do now?**

The project combines mobile technology, AI-assisted analysis, and a rule-based fallback architecture to explore a practical approach to accessible digital protection.

## ✨ Key Features

### 🔍 AI-Assisted Scam Detection
Analyze suspicious messages for potential phishing, impersonation, fraudulent payment requests, fake KYC alerts, deceptive offers, and other scam indicators.

### 🧠 Explainable Risk Assessment
Present risk classifications alongside understandable explanations and detected red flags, helping users make informed decisions instead of relying on an unexplained warning.

### 🗣️ Accessible, Regional-Language Guidance
Designed around the goal of making digital safety understandable to users who prefer simple language and regional-language explanations, including Hindi and Punjabi.

### 🛡️ Actionable Protection
Provide practical recommendations, such as avoiding suspicious links, never sharing OTPs or PINs, and verifying requests through official channels.

### 📱 Mobile-First Experience
Bring scam-analysis capabilities into an accessible Android application so users can seek guidance without needing specialized cybersecurity knowledge.

### ⚡ Multi-Layered Analysis
Explore a combination of on-device AI inference, backend-based analysis, and rule-based fallback mechanisms to support different execution scenarios.

### 🔔 Notification-Aware Protection
The architecture includes a notification-analysis workflow intended to help identify potentially risky messages when the relevant Android permissions and functionality are available.

*Feature availability depends on the implemented and configured components of the submitted build.*

---

## ⚙️ How It Works

<pre>
  Suspicious Message
         │
         ▼
  ┌──────────────────────┐
  │  KavachX Bharat App  │
  │  Message Submission  │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │   Analysis Pipeline  │
  │                      │
  │ • AI-assisted        │
  │   analysis           │
  │ • Risk indicators    │
  │ • Rule-based fallback│
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │   Risk Assessment    │
  │                      │
  │ Risk level           │
  │ Explanation          │
  │ Red flags            │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Actionable Guidance │
  │                      │
  │ Understand the risk  │
  │ Avoid unsafe actions │
  │ Verify independently │
  └──────────────────────┘
</pre>

### The user journey

1. **Submit:** The user enters a suspicious message through the mobile application.
2. **Analyze:** The configured analysis pipeline evaluates the message using the available detection mechanism.
3. **Understand:** The app presents the risk assessment and explains potential warning signs.
4. **Act safely:** The user receives recommendations for avoiding potential fraud and verifying the message.
5. **Stay informed:** Where supported, notification-based analysis can help bring attention to potentially suspicious communications.

---

## 🧠 Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Mobile frontend | Flutter, Dart | Cross-platform UI and Android application |
| Native Android integration | Kotlin | Android-specific capabilities and native integration |
| AI model | Google Gemma 4 E4B | Language-model-based analysis where configured |
| On-device inference | LiteRT-LM | Explore local model execution on supported devices |
| Backend API | Python, FastAPI | Message-analysis endpoints and backend services |
| Detection fallback | Rule-based analysis | Baseline analysis when AI inference is unavailable |

### Why this architecture?

**AI for contextual understanding.** Language models can help interpret the context and wording of suspicious communications when correctly configured.

**Rules for predictable fallback behavior.** A lightweight detection path provides a baseline when the model or backend cannot be reached.

**Mobile for accessibility.** The application brings security guidance closer to the point where users encounter suspicious messages.

**A modular foundation for future improvements.** Separating the mobile application, backend API, and analysis components makes it easier to improve detection and add capabilities independently.

---

## 🔐 Privacy, Safety and Responsible AI

Security software should protect users without creating a false sense of certainty.

KavachX Bharat is designed with the following principles in mind:

- **Understandable explanations:** Help users understand why a message may be suspicious.
- **Privacy-conscious architecture:** Explore on-device inference as an option for reducing the need to send message content to a remote service.
- **Fallback resilience:** Provide baseline analysis when the configured AI service is unavailable.
- **Honest risk communication:** Treat classifications as assessments, not guarantees.
- **Human decision-making:** Encourage independent verification before users transfer money, share credentials, or disclose sensitive information.

On-device inference does not automatically guarantee complete privacy. Actual data handling depends on the configured execution path, permissions, logging, and backend behavior.

---

## 🎯 Who Benefits?

- **Elderly users** who may be targeted by impersonation and financial scams.
- **First-time smartphone users** learning to navigate digital payments and online services.
- **Students and job seekers** who may encounter fraudulent offers or recruitment messages.
- **Everyday digital payment users** receiving suspicious banking, KYC, or refund messages.
- **Regional-language users** who benefit from accessible, understandable security guidance.

## 🌍 Vision and Impact

Our vision is to make digital safety more inclusive across India.

KavachX Bharat aims to move beyond simply labelling a message as suspicious. By combining detection, explanation, and practical guidance, it seeks to help users build the confidence to question suspicious requests before taking action.

The larger goal is a digital environment where **cybersecurity is not limited to technical experts—it is understandable to everyone.**

## 🚀 Future Scope

Potential areas for further development include:

- Expanded Hindi and Punjabi explanations, including voice-based guidance.
- More comprehensive phishing and malicious-link analysis.
- Improved contextual detection and evaluation against diverse scam examples.
- On-device model optimization for supported low-resource devices.
- Notification-based risk alerts with transparent permissions and user controls.
- User-controlled analysis history and privacy settings.
- Evaluation of detection accuracy, false positives, and false negatives on representative datasets.

These are future directions, not claims that every capability is already implemented.

## 🧪 Demo and Evaluation

For the hackathon demonstration, the core workflow should show:

1. A suspicious message being submitted.
2. The analysis response being generated.
3. A risk classification and explanation being displayed.
4. Relevant red flags and safety recommendations being presented.
5. A benign message being evaluated as a comparison.
6. The fallback behavior, if implemented and available, when the AI service cannot be reached.

A successful demonstration should show not only the result, but also how the result helps a user make a safer decision.

## ⚠️ Disclaimer

KavachX Bharat is an assistive digital-safety tool, not a guarantee against fraud. Automated analysis can produce false positives and false negatives. A message classified as safe may still be malicious.

Users should independently verify financial requests, links, account warnings, and requests for sensitive information through official channels.

## 🤝 Contributing

Contributions, issue reports, suggestions, and improvements are welcome. Help us make digital safety more accessible, understandable, and effective.

1. Fork the repository.
2. Create a feature branch.
3. Make and test your changes.
4. Submit a pull request describing the improvement.

## 📜 License

Add the license applicable to this project and ensure the repository contains the corresponding license file before claiming a particular license.

---

<div align="center">

### 🛡️ KavachX Bharat

**Detect the risk. Understand the threat. Take control.**

*Making digital safety understandable for everyone.*

</div>
