"""
KavachX Bharat — Preset Demo Scenarios
Provides deterministic, realistic scenarios for evaluation, demonstrations, and tests.
"""

from typing import List, Optional
from app.models.schemas import DemoScenario

DEMO_SCENARIOS: List[DemoScenario] = [
    DemoScenario(
        id="demo_digital_arrest",
        name="Digital Arrest Scam",
        description="Impersonates CBI/Police threatening immediate arrest unless funds are transferred.",
        input_text=(
            "This is CBI. Your bank account is linked to a money laundering case under investigation. "
            "You are under digital arrest. Stay on this video call and do not tell anyone. "
            "Transfer Rs 2,00,000 immediately to the secure government account to avoid arrest. "
            "Your Aadhaar is linked to illegal activity. If you disconnect, a warrant will be issued."
        ),
        input_type="call_transcript",
        expected_scam_type="Digital Arrest Scam",
        expected_risk_level="HIGH_RISK",
    ),
    DemoScenario(
        id="demo_fake_bank",
        name="Fake Bank Support",
        description="Fake customer care claiming account deactivation and demanding OTP and card details.",
        input_text=(
            "Dear Customer, this is SBI Customer Care. Your account will be blocked within 24 hours "
            "due to incomplete KYC verification. Please share your Aadhaar number and OTP sent to "
            "your registered mobile number immediately to avoid account suspension. "
            "Call us at 9876543210 for immediate resolution. Your account number ending in 4521."
        ),
        input_type="sms",
        expected_scam_type="Fake Bank Support",
        expected_risk_level="HIGH_RISK",
    ),
    DemoScenario(
        id="demo_investment",
        name="Investment Scam",
        description="Guaranteed 200% return scheme enticing victims into unverified trading groups.",
        input_text=(
            "EXCLUSIVE OFFER! Join our premium stock trading group on Telegram. "
            "We guarantee 200% returns in just 30 days! Invest Rs 50,000 today and earn Rs 1,50,000. "
            "Zero risk, 100% profit guaranteed. Limited slots available — act now! "
            "Our expert traders use AI to predict the market. Join now: t.me/faketrading"
        ),
        input_type="whatsapp",
        expected_scam_type="Investment Scam",
        expected_risk_level="VERIFY",
    ),
    DemoScenario(
        id="demo_task_scam",
        name="Prepaid Task / Job Scam",
        description="Online task/job scam requiring registration fee or deposit.",
        input_text=(
            "Hi! We have a simple work-from-home opportunity. Complete online rating tasks and "
            "earn Rs 500 per task. Daily income up to Rs 5000! Just pay a one-time registration fee "
            "of Rs 999 to join our Telegram group. Start earning immediately after registration. "
            "Pay via UPI to get instant access to tasks. Limited positions available!"
        ),
        input_type="whatsapp",
        expected_scam_type="Prepaid Task / Job Scam",
        expected_risk_level="VERIFY",
    ),
    DemoScenario(
        id="demo_phishing",
        name="Phishing SMS",
        description="Urgent account blocking alert with spoofed banking link.",
        input_text=(
            "URGENT: Your SBI account will be blocked today due to expired KYC. "
            "Verify your KYC immediately to avoid account suspension. "
            "Click here to update: http://sbi-kyc-update.fake-link.com/verify "
            "This is your last chance to prevent account deactivation."
        ),
        input_type="sms",
        expected_scam_type="Phishing",
        expected_risk_level="HIGH_RISK",
    ),
    DemoScenario(
        id="demo_upi_scam",
        name="UPI / Payment Scam",
        description="Reverse PIN deception asking user to enter UPI PIN to receive money.",
        input_text=(
            "Congratulations! You have received a cashback reward of Rs 3,500. "
            "Scan this QR code and enter your UPI PIN to claim and credit the amount to your bank account immediately."
        ),
        input_type="whatsapp",
        expected_scam_type="UPI / Payment Scam",
        expected_risk_level="VERIFY",
    ),
    DemoScenario(
        id="demo_legitimate",
        name="Safe / Legitimate Message",
        description="Normal personal communication that receives a SAFE risk score.",
        input_text=(
            "Hey! Are we still on for dinner at 7 PM tonight? I was thinking we could try that "
            "new restaurant near the station. Let me know if the timing works for you. "
            "Also, don't forget to bring the notes!"
        ),
        input_type="text",
        expected_scam_type="Legitimate",
        expected_risk_level="SAFE",
    ),
]


def get_demo_scenarios() -> List[DemoScenario]:
    """Return all available preset demo scenarios."""
    return DEMO_SCENARIOS


def get_demo_scenario_by_id(scenario_id: str) -> Optional[DemoScenario]:
    """Retrieve scenario by ID."""
    for s in DEMO_SCENARIOS:
        if s.id == scenario_id:
            return s
    return None
