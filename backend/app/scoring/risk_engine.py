"""
KavachX Bharat — Risk Scoring Engine
Deterministic, explainable risk scoring based on detected fraud signals.
Works alongside AI classification and ensures transparent, reproducible results.

Scoring Policy & Thresholds:
- SAFE:      0–29
- VERIFY:    30–64
- HIGH_RISK: 65–100
"""

import re
from typing import List, Tuple
from app.models.schemas import RiskScoreBreakdown, RiskLevel, ScamType

RISK_SIGNALS = [
    {
        "signal": "Government / Law Enforcement Impersonation",
        "points": 25,
        "patterns": [
            r"\b(cbi|police|customs|narcotics|enforcement\s*directorate|ministry|ncrb|rbi|sebi|income\s*tax|ed\b|nia\b)\b",
            r"\b(officer|inspector|commissioner|superintendent|magistrate|judge)\b.*\b(cbi|police|customs|cyber\s*cell|crime\s*branch)\b",
            r"\b(this is|i am|we are|calling from)\s+(the\s+)?(cbi|police|customs|cyber\s*cell|crime\s*branch)\b",
            r"\b(digital\s+arrest)\b",
        ],
        "description": "The message impersonates a government or law-enforcement authority."
    },
    {
        "signal": "Arrest / Legal Threat",
        "points": 25,
        "patterns": [
            r"\b(arrest|warrant|jail|prison|custody|detained|court\s*order|fir|criminal\s*case)\b",
            r"\b(under\s+investigation|money\s*laundering|illegal\s*activity|criminal\s*offense)\b",
            r"\b(you\s+will\s+be\s+arrested|avoid\s+arrest|prevent\s+arrest|face\s+arrest)\b",
        ],
        "description": "The message threatens arrest or legal prosecution to create fear."
    },
    {
        "signal": "Confirmed Malicious URL",
        "points": 40,
        "patterns": [
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Direct IP address
            r"\.(apk|exe|scr|bat)(\?|$)",                      # Executable or APK download
            r"https?://[^\s]*(yono|sbi|hdfc|icici|axis|pnb|kyc)[^\s]*\.(xyz|top|club|site|online|tk|ml|ga|cf|gq|work|rest|buzz|click|cc)(\/|$)",
            r"https?://[^\s]*(-sbi|-hdfc|-bank|-kyc|fake-sbi|sbi-kyc|fake-link|verify-fraud)[^\s]*",
        ],
        "description": "The message contains a confirmed malicious, phishing, or spoofed URL."
    },
    {
        "signal": "Explicit Request to Disclose OTP / PIN",
        "points": 30,
        "patterns": [
            r"\b(share|send|provide|tell|forward|submit|enter|input|reply\s+with)\s+(your\s+)?(otp|pin|password|cvv|mpin|upi\s*pin|verification\s*code)\b",
            r"\b(enter|use|input)\s+(your\s+)?(upi\s*pin|pin)\s+(to\s+)?(receive|claim|get)\s+(money|funds|cashback|refund)\b",
            r"\b(ask(ing)?\s+for|demands?)\s+(your\s+)?(otp|pin|password|cvv)\b",
            r"\b(otp|pin)\s+(required|needed)\s+to\s+(unblock|verify|activate|avoid|receive)\b",
            r"(अपना|ਆਪਣਾ)\s*(otp|pin|पासवर्ड|ਪਾਸਵਰਡ)\s*(भेजें|ਦੱਸੋ|ਸਾਂਝਾ|share|send|bhejo)",
            r"\b(otp|pin|password|cvv)\b.*\b(bhejo|share|enter|send|karein|karo|daso|sanjha)\b",
        ],
        "description": "The message explicitly asks the recipient to disclose an OTP, PIN, or verification code."
    },
    {
        "signal": "Request for Sensitive Credentials",
        "points": 25,
        "patterns": [
            r"\b(enter|share|provide|update|send)\s+(your\s+)?(card\s*number|card\s*details|debit\s*card|credit\s*card|cvv|expiry|net\s*banking\s*password|banking\s*password|login\s*password|internet\s*banking)\b",
            r"\b(share|provide|send)\s+(your\s+)?(aadhaar|aadhar|pan\s*card)\b.*\b(otp|pin|password|card)\b",
        ],
        "description": "The message requests sensitive banking credentials, passwords, or card details."
    },
    {
        "signal": "Urgent Payment / Money Request",
        "points": 20,
        "patterns": [
            r"\b(transfer|send|pay|deposit)\s+(money|funds|amount|₹|\$|rs\.?|rupees?|inr|cash)(\s*[\d,]+)?\s*(immediately|urgently|right\s*now|within|to\s+avoid|to\s+secure)?\b",
            r"\b(transfer|send|pay|deposit)\b.*\b(fee|tax|charge|amount|money|₹|rs)\b",
            r"\b(transfer\s+funds|send\s+money|make\s+payment)\s+(immediately|to\s+avoid|now)\b",
            r"\b(invest)\s+(₹|rs\.?)\s*[\d,]+",
        ],
        "description": "The message demands an urgent transfer of money or fee payment."
    },
    {
        "signal": "Investment / Returns Guarantee",
        "points": 20,
        "patterns": [
            r"\b(guaranteed\s+(returns?|profit|income)|100%\s*(safe|returns?|profit)|zero\s*risk|no\s*risk)\b",
            r"\b(\d+%\s*(daily|weekly|monthly|returns?|profit))\b",
            r"\b(double\s+your\s+money|triple\s+your\s+money|2x|3x|5x|10x\s+returns?)\b",
            r"\b(crypto\s+trading\s+group|stock\s+tips\s+group|forex\s+trading|bitcoin\s+investment)\b",
            r"\b(earn\s+(daily|passive)\s+income\s+from\s+home)\b",
        ],
        "description": "The message promises unrealistic or guaranteed financial returns."
    },
    {
        "signal": "Prepaid Task / Job Fraud",
        "points": 20,
        "patterns": [
            r"\b(complete\s+(tasks?|reviews?|ratings?)|rate\s+apps?|like\s+videos?|subscribe\s+channel)\b",
            r"\b(work\s+from\s+home|part\s*time\s*job)\b.*\b(earn|salary|daily|per\s+day)\b",
            r"\b(registration\s+fee|security\s+deposit|joining\s+fee|activation\s+charge)\b",
            r"\b(prepaid\s+task|task\s+based\s+earning|telegram\s+task)\b",
        ],
        "description": "The message promotes a prepaid task or job requiring upfront payment."
    },
    {
        "signal": "Bank / KYC Impersonation",
        "points": 20,
        "patterns": [
            r"\b(sbi|hdfc|icici|axis|pnb|bob|canara|union\s*bank|kotak|bank\s*account)\b.*\b(blocked|suspended|deactivated|frozen|hold|restricted)\b",
            r"\b(account|card|debit\s*card|credit\s*card|net\s*banking)\b.*\b(blocked|suspended|frozen|restricted|expired)\b",
            r"\b(update|complete|verify|link)\s+(your\s+)?(kyc|pan|aadhaar|aadhar)\b",
            r"\b(kyc\s+(suspended|expired|pending|incomplete|mandatory))\b",
        ],
        "description": "The message impersonates a bank or threatens account suspension regarding KYC."
    },
    {
        "signal": "Bank / KYC Verification Advisory",
        "points": 30,
        "patterns": [
            r"\b(account\s+will\s+be\s+(blocked|closed|suspended|deactivated)\s+(today|within|immediately))\b",
            r"\b(verify\s+immediately|update\s+now\s+to\s+avoid)\b",
        ],
        "description": "The message creates severe pressure regarding immediate bank account closure."
    },
    {
        "signal": "Utility / Electricity Bill Threat",
        "points": 25,
        "patterns": [
            r"\b(electricity|power|water|gas)\s*(bill|connection|supply)\b.*\b(disconnect|cut|suspended|stopped)\b",
            r"\b(disconnected\s+tonight|power\s+cut\s+at)\b",
            r"\b(contact\s+electricity\s+officer|call\s+electricity\s+helpline)\b",
        ],
        "description": "The message threatens imminent disconnection of vital utility services."
    },
    {
        "signal": "Lottery / Prize / Reward Scam",
        "points": 18,
        "patterns": [
            r"\b(won|winner|winning|selected\s+for)\s+(a\s+)?(lottery|prize|reward|car|iphone|cash|crore|lakh|lucky\s*draw)\b",
            r"\b(congratulations|kbc|kaun\s+banega\s+crorepati|jio\s*lucky\s*draw)\b",
            r"\b(claim\s+your\s+(prize|reward|winnings?|lottery))\b",
        ],
        "description": "The message falsely claims the recipient has won an unsolicited prize or lottery."
    },
    {
        "signal": "UPI / Payment Fraud",
        "points": 18,
        "patterns": [
            r"\b(collect\s+request|payment\s+request)\b.*\b(phonepe|paytm|gpay|google\s*pay|bhim|upi)\b",
            r"\b(scan\s+(this\s+)?qr\s*code\s+to\s+(receive|get|claim)\s+(money|cashback|refund))\b",
            r"\b(enter\s+upi\s+pin\s+to\s+receive)\b",
            r"\b(sent\s+you\s+money|credited\s+via\s+upi)\b.*\b(approve|accept|click)\b",
        ],
        "description": "The message attempts UPI payment deception or reverse collect request scam."
    },
    {
        "signal": "Aadhaar / Identity Threat",
        "points": 18,
        "patterns": [
            r"\b(aadhaar|aadhar|identity)\b.*\b(misused|involved\s+in|used\s+in\s+illegal|fraud)\b",
            r"\b(sim\s*card(s)?\s*(issued|registered)\s+in\s+your\s+name)\b",
        ],
        "description": "The message claims the recipient's identity or Aadhaar has been compromised."
    },
    {
        "signal": "Fear / Psychological Coercion",
        "points": 15,
        "patterns": [
            r"\b(do\s+not\s+tell\s+anyone|don'?t\s+tell|keep\s+this\s+secret|confidential)\b",
            r"\b(stay\s+on\s+(the\s+)?(call|video\s*call|line)|do\s+not\s+disconnect|don'?t\s+hang\s*up)\b",
            r"\b(last\s+chance|final\s+warning|no\s+other\s+option|only\s+way)\b",
        ],
        "description": "The message uses secrecy, isolation, or extreme urgency to manipulate the victim."
    },
    {
        "signal": "Suspicious or Unverified URL",
        "points": 15,
        "patterns": [
            r"\b(bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cutt\.ly|shorturl\.at|rb\.gy)\b",
            r"\bhttp://[^\s]+",
            r"https?://[^\s]+",
        ],
        "description": "The message contains an embedded or shortened link that obscures the true destination."
    },
    {
        "signal": "Generic Urgency Language",
        "points": 5,
        "patterns": [
            r"\b(urgently|immediately|right\s*now|within\s+\d+\s*(hours?|mins?|minutes?|days?)|turant|jaldi|without\s+delay|last\s+chance|final\s+warning|hurry)\b",
        ],
        "description": "The message creates artificial urgency."
    },
]


def calculate_risk_score(text: str) -> Tuple[int, RiskLevel, List[RiskScoreBreakdown]]:
    """
    Calculate a deterministic, explainable risk score from 0 to 100 based on detected signals.

    Thresholds:
      - SAFE: 0–29
      - VERIFY: 30–64
      - HIGH_RISK: 65–100

    Returns:
        Tuple of (score, risk_level, breakdown)
    """
    text_lower = text.lower()
    total_score = 0
    breakdown = []

    # 1. Check for explicit safety reminders in legitimate bank / security notices
    has_safety_warning = bool(re.search(
        r"\b(never\s+share|do\s+not\s+share|don'?t\s+share|bank\s+never\s+asks|never\s+ask\s+for\s+otp|bank\s+never\s+calls)\b",
        text_lower
    ))
    has_active_solicitation = bool(re.search(
        r"\b(send|submit|forward|enter|tell|reply\s+with|share)\s+(your\s+)?(otp|pin|password|cvv)\b",
        text_lower
    ))

    # 2. Check for legitimate transactional or parcel delivery updates
    is_legitimate_transaction = bool(re.search(
        r"\b(credited\s+with|debited\s+for|available\s+balance|balance\s+is|txn\s+of|transaction\s+of|"
        r"out\s+for\s+delivery|delivered\s+today|order\s+confirmed|shipped\s+today|tracking\s+number)\b",
        text_lower
    ))

    has_confirmed_malicious_url = False

    for signal_def in RISK_SIGNALS:
        sig_name = signal_def["signal"]

        # Prevent double-counting: if confirmed malicious URL was matched, skip generic unverified URL
        if sig_name == "Suspicious or Unverified URL" and has_confirmed_malicious_url:
            continue

        # Prevent false positive: do not flag OTP if message is a safety reminder without solicitation
        if sig_name == "Explicit Request to Disclose OTP / PIN" and has_safety_warning and not has_active_solicitation:
            continue

        matched = False
        for pattern in signal_def["patterns"]:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched = True
                break

        if matched:
            if sig_name == "Confirmed Malicious URL":
                has_confirmed_malicious_url = True

            total_score += signal_def["points"]
            breakdown.append(RiskScoreBreakdown(
                signal=sig_name,
                points=signal_def["points"],
                description=signal_def["description"]
            ))

    # 3. Legitimate transaction dampener:
    # If the message is a legitimate bank credit/debit or parcel delivery notification
    # AND has no credential harvesting, no malicious URL, no arrest threat, and no payment demand:
    has_severe_threat = any(b.signal in (
        "Confirmed Malicious URL",
        "Explicit Request to Disclose OTP / PIN",
        "Request for Sensitive Credentials",
        "Government / Law Enforcement Impersonation",
        "Arrest / Legal Threat",
        "Urgent Payment / Money Request"
    ) for b in breakdown)

    if (is_legitimate_transaction or (has_safety_warning and not has_active_solicitation)) and not has_severe_threat:
        total_score = 0
        breakdown = []

    # 4. Normalize and clamp final score strictly between 0 and 100
    score = max(0, min(total_score, 100))

    # 5. Determine category based on specified thresholds
    risk_level = get_risk_level_from_score(score)

    return score, risk_level, breakdown


def classify_scam_type(text: str, breakdown: List[RiskScoreBreakdown]) -> str:
    """
    Classify the scam type based on detected signals and contextual keywords.
    Uses priority ordering — the most specific/dangerous type wins.
    """
    text_lower = text.lower()
    signal_names = {b.signal for b in breakdown}

    # If score < 30 and no signals, it is Legitimate
    if not breakdown:
        return ScamType.LEGITIMATE.value

    # Digital Arrest Scam: government impersonation + arrest / legal / payment threat
    if ("Government / Law Enforcement Impersonation" in signal_names and "Arrest / Legal Threat" in signal_names) or (
        "Government / Law Enforcement Impersonation" in signal_names and "Urgent Payment / Money Request" in signal_names
    ) or (
        "Arrest / Legal Threat" in signal_names and "Urgent Payment / Money Request" in signal_names
    ) or ("digital arrest" in text_lower):
        return ScamType.DIGITAL_ARREST.value

    if "Arrest / Legal Threat" in signal_names:
        return ScamType.DIGITAL_ARREST.value

    if "Government / Law Enforcement Impersonation" in signal_names:
        return ScamType.GOVERNMENT_IMPERSONATION.value

    # Phishing: suspicious links or confirmed malicious URL with bank or credentials
    if ("Confirmed Malicious URL" in signal_names or "Suspicious or Unverified URL" in signal_names) and (
        "Request for Sensitive Credentials" in signal_names or
        "Explicit Request to Disclose OTP / PIN" in signal_names or
        "Bank / KYC Impersonation" in signal_names or
        "Bank / KYC Verification Advisory" in signal_names
    ):
        return ScamType.PHISHING.value

    # Fake Bank Support
    if "Bank / KYC Impersonation" in signal_names or "Bank / KYC Verification Advisory" in signal_names:
        if "Confirmed Malicious URL" in signal_names or "Suspicious or Unverified URL" in signal_names:
            return ScamType.PHISHING.value
        return ScamType.FAKE_BANK_SUPPORT.value

    # Lottery / Prize Scam
    if "Lottery / Prize / Reward Scam" in signal_names or any(w in text_lower for w in ("lottery", "kbc", "prize", "lucky draw", "jackpot", "winner")):
        return ScamType.LOTTERY_PRIZE_SCAM.value

    # Prepaid Task / Job Scam
    if "Prepaid Task / Job Fraud" in signal_names or any(w in text_lower for w in ("work from home", "part time job", "rating task", "review task")):
        return ScamType.PREPAID_TASK_SCAM.value

    # Investment Scam
    if "Investment / Returns Guarantee" in signal_names:
        return ScamType.INVESTMENT_SCAM.value

    # UPI / Payment Scam
    if "UPI / Payment Fraud" in signal_names:
        return ScamType.UPI_PAYMENT_SCAM.value

    # Utility bill threat
    if "Utility / Electricity Bill Threat" in signal_names:
        return ScamType.PHISHING.value

    if "Explicit Request to Disclose OTP / PIN" in signal_names or "Request for Sensitive Credentials" in signal_names:
        return ScamType.PHISHING.value

    if "Confirmed Malicious URL" in signal_names or "Suspicious or Unverified URL" in signal_names:
        return ScamType.PHISHING.value

    if "Aadhaar / Identity Threat" in signal_names:
        return ScamType.GOVERNMENT_IMPERSONATION.value

    if len(breakdown) > 0:
        return "Unknown Scam Type"

    return ScamType.LEGITIMATE.value


def get_risk_level_from_score(score: int) -> RiskLevel:
    """
    Convert a numeric score (0-100) to standard RiskLevel:
    - SAFE: 0–29
    - VERIFY: 30–64
    - HIGH_RISK: 65–100
    """
    if score >= 65:
        return RiskLevel.HIGH_RISK
    elif score >= 30:
        return RiskLevel.VERIFY
    else:
        return RiskLevel.SAFE
