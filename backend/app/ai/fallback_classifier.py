"""
KavachX Bharat — Deterministic Fallback Classifier
Rules-based analyzer providing safe, explainable fraud classification
with zero reliance on external APIs, cloud services, or heavy weights.
"""

from typing import List, Dict
from app.models.schemas import (
    AnalysisResult, RedFlag, RiskLevel, InputType, Verdict, ScamType
)
from app.scoring.risk_engine import (
    calculate_risk_score, classify_scam_type, get_risk_level_from_score
)

SCAM_RED_FLAGS: Dict[str, List[RedFlag]] = {
    ScamType.DIGITAL_ARREST.value: [
        RedFlag(indicator="Digital Arrest Coercion", description="Threatens immediate arrest via video call or telephone.", severity="critical"),
        RedFlag(indicator="Law Enforcement Impersonation", description="Pretends to be an officer from CBI, Cyber Police, ED, or Customs.", severity="critical"),
        RedFlag(indicator="Urgent Fund Transfer", description="Demands money transfer to 'verify' funds or avoid custody.", severity="critical"),
        RedFlag(indicator="Psychological Isolation", description="Demands confidentiality and forbids speaking to family or lawyers.", severity="high"),
    ],
    ScamType.FAKE_BANK_SUPPORT.value: [
        RedFlag(indicator="Credential Harvesting", description="Requests confidential OTP, PIN, password, or card CVV.", severity="critical"),
        RedFlag(indicator="Account Blocking Threat", description="Threatens immediate account closure or suspension.", severity="high"),
        RedFlag(indicator="Unauthorized Bank Impersonation", description="Pretends to be customer support from an official financial institution.", severity="high"),
    ],
    ScamType.INVESTMENT_SCAM.value: [
        RedFlag(indicator="Guaranteed Returns", description="Promises unrealistic guaranteed profits or daily income.", severity="critical"),
        RedFlag(indicator="Zero Risk Claims", description="Falsely claims investment has zero risk or 100% safety.", severity="high"),
        RedFlag(indicator="Unregistered Platform", description="Directs victim to unverified Telegram groups or trading apps.", severity="high"),
    ],
    ScamType.PREPAID_TASK_SCAM.value: [
        RedFlag(indicator="Upfront Payment Required", description="Demands registration fee, deposit, or task recharge.", severity="critical"),
        RedFlag(indicator="Unrealistic Task Earnings", description="Offers lucrative pay for simple YouTube likes or review tasks.", severity="medium"),
        RedFlag(indicator="Group Recruitment", description="Funneling into private Telegram or WhatsApp groups.", severity="medium"),
    ],
    ScamType.PHISHING.value: [
        RedFlag(indicator="Suspicious URL", description="Directs to unverified, shortened, or spoofed web link.", severity="critical"),
        RedFlag(indicator="Credential Theft Pretext", description="Fake portal designed to steal login credentials or banking info.", severity="critical"),
        RedFlag(indicator="Artificial Urgency", description="Urges immediate action to avoid penalty or loss.", severity="high"),
    ],
    ScamType.UPI_PAYMENT_SCAM.value: [
        RedFlag(indicator="Reverse PIN Deception", description="Requests UPI PIN to receive money (PIN is strictly for sending).", severity="critical"),
        RedFlag(indicator="Fraudulent Collect Request", description="Sends a debit request disguised as an incoming refund.", severity="critical"),
        RedFlag(indicator="QR Code Scam", description="Instructs victim to scan QR code to receive cashback or lottery.", severity="high"),
    ],
    ScamType.GOVERNMENT_IMPERSONATION.value: [
        RedFlag(indicator="Official Body Impersonation", description="Claims to represent government agencies, courts, or regulators.", severity="high"),
        RedFlag(indicator="Aadhaar / ID Misuse Claim", description="Alleges identity misuse to cause panic.", severity="high"),
        RedFlag(indicator="Unofficial Channel Notice", description="Conducts official legal business via SMS or WhatsApp.", severity="high"),
    ],
    ScamType.LOTTERY_PRIZE_SCAM.value: [
        RedFlag(indicator="Unsolicited Lottery Winnings", description="Claims you won a lottery or prize you never entered.", severity="high"),
        RedFlag(indicator="Advance Processing Fee", description="Demands tax or processing fees before releasing the prize.", severity="critical"),
        RedFlag(indicator="Sensationalized Rewards", description="Offers unrealistically large cash prizes or luxury items.", severity="medium"),
    ],
}

SAFETY_RECOMMENDATIONS: Dict[str, List[str]] = {
    ScamType.DIGITAL_ARREST.value: [
        "No Indian law enforcement agency or court conducts arrests over telephone or video calls.",
        "Do NOT transfer any money or disclose your bank account details.",
        "Disconnect the call immediately and inform family members or local police.",
        "Report the call immediately to the National Cyber Crime Helpline at 1930.",
        "File a complaint at the official portal: cybercrime.gov.in",
    ],
    ScamType.FAKE_BANK_SUPPORT.value: [
        "Banks NEVER ask for OTP, PIN, passwords, or CVV over SMS, phone, or email.",
        "Do NOT share your OTP, card details, or internet banking password.",
        "Never click on links received via SMS claiming to update KYC.",
        "Contact your bank directly using the official phone number on your bank passbook/card.",
        "Report suspicious messages to 1930 and your bank's fraud prevention team.",
    ],
    ScamType.INVESTMENT_SCAM.value: [
        "No legitimate investment offers guaranteed high returns with zero risk.",
        "Do NOT send funds to personal UPI IDs or unverified crypto/trading platforms.",
        "Verify intermediaries on the SEBI official registry before investing.",
        "Leave unknown investment groups on Telegram or WhatsApp immediately.",
        "Report financial fraud to 1930.",
    ],
    ScamType.PREPAID_TASK_SCAM.value: [
        "Legitimate companies never ask employees or freelancers for upfront deposits to work.",
        "Do NOT pay any registration or activation fee for online tasks.",
        "Stop sending money immediately even if promised a refund with interest.",
        "Exit suspicious Telegram task groups and report the organizers to 1930.",
    ],
    ScamType.PHISHING.value: [
        "Do NOT click on unverified links or download APK files from SMS/WhatsApp.",
        "Verify the website address carefully — scam domains mimic official brand names.",
        "If you entered credentials, change your passwords immediately and notify your bank.",
        "Enable two-factor authentication on all sensitive accounts.",
        "Report phishing links to cybercrime.gov.in and 1930.",
    ],
    ScamType.UPI_PAYMENT_SCAM.value: [
        "You NEVER need to enter your UPI PIN to receive money or refunds.",
        "Do NOT approve collect requests received from unknown senders on PhonePe/GPay/Paytm.",
        "Never scan a QR code sent by a buyer or stranger claiming to transfer money.",
        "Verify account balance only inside your official banking or UPI app.",
        "Report fraudulent UPI IDs to your payment service provider and 1930.",
    ],
    ScamType.GOVERNMENT_IMPERSONATION.value: [
        "Government ministries and regulators do not send legal summons or threats over WhatsApp.",
        "Do NOT transfer money to clear fake electricity bills, challans, or court cases.",
        "Verify electricity or bill status directly on your official power utility provider portal.",
        "Report impersonation attempts to cybercrime.gov.in.",
    ],
    ScamType.LOTTERY_PRIZE_SCAM.value: [
        "You cannot win a lottery or contest that you never entered.",
        "Never pay any 'processing fee', 'GST', or 'release charge' to claim a prize.",
        "Do not provide personal or banking information to claim winnings.",
        "Block the sender and report the incident to 1930.",
    ],
}

LOCALIZED_RECOMMENDATIONS = {
    "hi": [
        "किसी भी अज्ञात व्यक्ति, खाते या लिंक पर पैसे ट्रांसफर न करें।",
        "अपना OTP, UPI PIN, पासवर्ड या बैंक विवरण कभी किसी के साथ साझा न करें।",
        "कोई भी भारतीय सरकारी एजेंसी फोन या वीडियो कॉल पर डिजिटल अरेस्ट नहीं करती।",
        "तुरंत राष्ट्रीय साइबर अपराध हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट दर्ज करें।"
    ],
    "pa": [
        "ਕਿਸੇ ਵੀ ਅਣਜਾਣ ਵਿਅਕਤੀ ਜਾਂ ਲਿੰਕ 'ਤੇ ਪੈਸੇ ਟ੍ਰਾਂਸਫਰ ਨਾ ਕਰੋ।",
        "ਆਪਣਾ OTP, UPI PIN, ਪਾਸਵਰਡ ਜਾਂ ਬੈਂਕ ਵੇਰਵੇ ਕਦੇ ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ।",
        "ਕੋਈ ਵੀ ਭਾਰਤੀ ਸਰਕਾਰੀ ਏਜੰਸੀ ਫ਼ੋਨ ਜਾਂ ਵੀਡੀਓ ਕਾਲ 'ਤੇ ਡਿਜੀਟਲ ਗ੍ਰਿਫ਼ਤਾਰੀ ਨਹੀਂ ਕਰਦੀ।",
        "ਤੁਰੰਤ ਰਾਸ਼ਟਰੀ ਸਾਈਬਰ ਕ੍ਰਾਈਮ ਹੈਲਪਲਾਈਨ 1930 'ਤੇ ਕਾਲ ਕਰੋ ਜਾਂ cybercrime.gov.in 'ਤੇ ਰਿਪੋਰਟ ਦਰਜ ਕਰੋ।"
    ],
    "hinglish": [
        "Kisi bhi unknown person ya link par paise transfer na karein.",
        "Apna OTP, UPI PIN, password ya bank details kabhi kisi ke sath share na karein.",
        "Koi bhi Indian government agency phone ya video call par digital arrest nahi karti.",
        "Turant National Cyber Crime Helpline 1930 par call karein ya cybercrime.gov.in par report darj karein."
    ]
}


def generate_explanation(scam_type: str, red_flags: List[RedFlag], risk_score: int, language: str = "en") -> str:
    """Generate a clear plain-language explanation of the analysis."""
    if language == "hi":
        if risk_score >= 65:
            return (
                f"चेतावनी (उच्च जोखिम): इस संदेश में धोखाधड़ी और ठगी के गंभीर संकेत मिले हैं ({scam_type})। "
                "किसी भी निर्देश का पालन न करें और अपनी वित्तीय या व्यक्तिगत जानकारी साझा न करें।"
            )
        elif risk_score >= 30:
            return (
                f"सत्यापन आवश्यक: यह संदेश संदिग्ध प्रतीत होता है ({scam_type})। "
                "कोई भी कदम उठाने से पहले आधिकारिक स्रोतों से पुष्टि करें।"
            )
        else:
            return "इस संदेश में किसी धोखाधड़ी के संकेत नहीं मिले हैं। यह सामान्य संचार प्रतीत होता है।"

    elif language == "pa":
        if risk_score >= 65:
            return (
                f"ਚੇਤਾਵਨੀ (ਉੱਚ ਜੋਖਮ): ਇਸ ਸੰਚਾਰ ਵਿੱਚ ਧੋਖਾਧੜੀ ਦੇ ਗੰਭੀਰ ਲੱਛਣ ਮਿਲੇ ਹਨ ({scam_type})। "
                "ਕਿਸੇ ਵੀ ਲਿੰਕ 'ਤੇ ਕਲਿੱਕ ਨਾ ਕਰੋ ਅਤੇ ਪੈਸੇ ਟ੍ਰਾਂਸਫਰ ਨਾ ਕਰੋ।"
            )
        elif risk_score >= 30:
            return (
                f"ਤਸਦੀਕ ਕਰੋ: ਇਹ ਸੁਨੇਹਾ ਸ਼ੱਕੀ ਜਾਪਦਾ ਹੈ ({scam_type})। "
                "ਕੋਈ ਵੀ ਕਦਮ ਚੁੱਕਣ ਤੋਂ ਪਹਿਲਾਂ ਅਧਿਕਾਰਤ ਤੌਰ 'ਤੇ ਜਾਂਚ ਕਰੋ।"
            )
        else:
            return "ਇਸ ਸੁਨੇਹੇ ਵਿੱਚ ਧੋਖਾਧੜੀ ਦਾ ਕੋਈ ਵੱਡਾ ਖ਼ਤਰਾ ਨਹੀਂ ਮਿਲਿਆ ਹੈ।"

    elif language == "hinglish":
        if risk_score >= 65:
            return (
                f"HIGH RISK WARNING: Is message mein scam aur fraud ke clear signs mile hain ({scam_type}). "
                "Kisi bhi link par click na karein aur koi bhi sensitive details ya paise transfer na karein."
            )
        elif risk_score >= 30:
            return (
                f"VERIFY CAREFULLY: Yeh communication suspicious lag rahi hai ({scam_type}). "
                "Koi bhi action lene se pehle official helpline ya branch se verify karein."
            )
        else:
            return "Is message mein koi fraud pattern nahi mila. Yeh safe aur legitimate communication lagti hai."

    # English default
    explanations = {
        ScamType.DIGITAL_ARREST.value: (
            "This communication impersonates law-enforcement officials and threatens immediate arrest or legal consequences "
            "to coerce the victim into transferring funds. This is a classic 'digital arrest' scam. "
            "No Indian law-enforcement agency conducts arrests through phone or video calls, and legitimate authorities "
            "never demand payment to settle criminal allegations."
        ),
        ScamType.FAKE_BANK_SUPPORT.value: (
            "This communication impersonates bank customer support and attempts to extract confidential financial "
            "credentials such as OTPs, PINs, or card details under the pretext of account security or KYC renewal. "
            "Legitimate banks never request passwords or PINs via unsolicited communication."
        ),
        ScamType.INVESTMENT_SCAM.value: (
            "This message promotes an investment scheme with unrealistic guaranteed returns and zero risk claims. "
            "No legitimate financial investment can guarantee fixed profits. This is designed to lure victims into "
            "unregulated deposit traps."
        ),
        ScamType.PREPAID_TASK_SCAM.value: (
            "This communication offers high pay for simple online rating or video tasks, but requires upfront registration "
            "fees or prepaid task deposits. Genuine employers never ask candidates to pay money to start work."
        ),
        ScamType.PHISHING.value: (
            "This communication contains suspicious links designed to harvest sensitive personal or banking credentials. "
            "The URLs mimic official institutions to deceive users into submitting passwords or downloading malicious files."
        ),
        ScamType.UPI_PAYMENT_SCAM.value: (
            "This communication attempts UPI payment deception by asking the recipient to enter their UPI PIN to 'receive' "
            "money or scan a QR code for a refund. UPI PINs are only required when sending money from your account."
        ),
        ScamType.GOVERNMENT_IMPERSONATION.value: (
            "This communication falsely claims to represent government bodies, regulators, or public utilities. "
            "Government agencies do not conduct official business, issue arrest notices, or collect fines via WhatsApp or SMS."
        ),
        ScamType.LOTTERY_PRIZE_SCAM.value: (
            "This message claims you have won an unsolicited lottery or luxury prize, but requires an advance processing fee. "
            "Legitimate lotteries do not ask winners to pay upfront fees to claim prizes."
        ),
    }

    base = explanations.get(
        scam_type,
        "This communication exhibits suspicious patterns commonly associated with fraudulent communications. "
        "Exercise extreme caution and verify the sender before taking any action."
    )

    if risk_score >= 65:
        return f"HIGH RISK: {base}"
    elif risk_score >= 30:
        return f"VERIFY: {base}"
    else:
        return base


def generate_summary(scam_type: str, risk_score: int, risk_level: str, language: str = "en") -> str:
    """Generate a concise one-line summary of the scan result."""
    if scam_type == ScamType.LEGITIMATE.value:
        if language == "hi":
            return "कोई महत्वपूर्ण धोखाधड़ी संकेत नहीं मिला। यह संदेश सुरक्षित प्रतीत होता है।"
        if language == "pa":
            return "ਕੋਈ ਸ਼ੱਕੀ ਧੋਖਾਧੜੀ ਨਹੀਂ ਮਿਲੀ। ਇਹ ਸੁਨੇਹਾ ਸੁਰੱਖਿਅਤ ਜਾਪਦਾ ਹੈ।"
        if language == "hinglish":
            return "Koi scam indicators detect nahi hue. Yeh message legitimate lagta hai."
        return "No significant scam indicators detected. The communication appears to be legitimate."

    if language == "hi":
        return f"कवचएक्स भारत ने इसे संभावित {scam_type} के रूप में वर्गीकृत किया है, जोखिम स्कोर {risk_score}/100 ({risk_level})।"
    if language == "pa":
        return f"ਕਵਚਐਕਸ ਭਾਰਤ ਨੇ ਇਸਨੂੰ ਸੰਭਾਵੀ {scam_type} ਵਜੋਂ ਪਛਾਣਿਆ ਹੈ, ਜੋਖਮ ਸਕੋਰ {risk_score}/100 ({risk_level})।"
    if language == "hinglish":
        return f"KavachX Bharat ne is message ko potential {scam_type} classify kiya hai, risk score {risk_score}/100 ({risk_level})."

    return (
        f"KavachX Bharat has classified this communication as a potential {scam_type} "
        f"with a risk score of {risk_score}/100 ({risk_level})."
    )


def analyze_with_fallback(text: str, input_type: str = "text", language: str = "en") -> AnalysisResult:
    """
    Deterministic rule-based fallback analysis pipeline.
    Produces comprehensive, explainable results without external dependencies.
    """
    # 1. Calculate risk score & breakdown
    risk_score, risk_level, score_breakdown = calculate_risk_score(text)

    # 2. Classify scam type
    scam_type = classify_scam_type(text, score_breakdown)

    # 3. Determine red flags
    red_flags = list(SCAM_RED_FLAGS.get(scam_type, []))
    if not red_flags and score_breakdown:
        red_flags = [
            RedFlag(
                indicator=b.signal,
                description=b.description,
                severity="critical" if b.points >= 30 else ("high" if b.points >= 20 else "medium")
            )
            for b in score_breakdown
        ]

    # 4. Resolve safety recommendations
    base_recs = SAFETY_RECOMMENDATIONS.get(scam_type, [
        "Exercise extreme caution with this communication.",
        "Do not share personal, banking, or credential information.",
        "Verify the sender's identity through official independent channels.",
        "Report suspicious activity to the National Cyber Crime Helpline at 1930.",
    ])

    if language in LOCALIZED_RECOMMENDATIONS and scam_type != ScamType.LEGITIMATE.value:
        recommendations = LOCALIZED_RECOMMENDATIONS[language] + list(base_recs[:2])
    else:
        recommendations = list(base_recs)

    # 5. Extract entities and evidence
    entities = [b.signal for b in score_breakdown]
    evidence = [f"{b.signal} ({b.points} pts): {b.description}" for b in score_breakdown]

    # 6. Verdict and confidence
    if risk_score >= 65:
        confidence = 0.90
        verdict = Verdict.LIKELY_SCAM.value
    elif risk_score >= 30:
        confidence = 0.75
        verdict = Verdict.SUSPICIOUS.value
    else:
        confidence = 0.95
        verdict = Verdict.LIKELY_LEGITIMATE.value

    # Handle legitimate message overrides
    if scam_type == ScamType.LEGITIMATE.value:
        red_flags = []
        if language in LOCALIZED_RECOMMENDATIONS:
            recommendations = [
                "यह संदेश सुरक्षित प्रतीत होता है।" if language == "hi" else (
                    "ਇਹ ਸੁਨੇਹਾ ਸੁਰੱਖਿਅਤ ਜਾਪਦਾ ਹੈ।" if language == "pa" else
                    "Yeh message safe lagta hai."
                ),
                "No immediate action is required.",
                "Always remain vigilant regarding unsolicited communications.",
            ]
        else:
            recommendations = [
                "This communication appears to be safe.",
                "No immediate action is required.",
                "Always remain vigilant regarding unsolicited communications.",
            ]
        verdict = Verdict.LIKELY_LEGITIMATE.value

    # 7. Generate localized explanation and summary
    explanation = generate_explanation(scam_type, red_flags, risk_score, language)
    summary = generate_summary(scam_type, risk_score, risk_level.value, language)

    return AnalysisResult(
        scam_type=scam_type,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        summary=summary,
        explanation=explanation,
        red_flags=red_flags,
        recommended_actions=recommendations,
        detected_entities=entities,
        score_breakdown=score_breakdown,
        input_type=input_type,
        input_text=text,
        ai_provider="fallback",
        verdict=verdict,
        evidence=evidence,
        signals=[b.signal for b in score_breakdown],
        analysis_mode="rules-only",
        analysis_complete=True,
        warnings=["Deterministic rule-based analysis engine used."],
        model_name="rule_engine",
        language=language,
        fallback_used=True,
        fallback_reason=None,
    )
