"""Sample F&I credit-application prompts for the Lakeside Auto Group demo.

All personal values here are fictional and obviously so (example.com email,
555 phone, well-known test Visa, reserved-style SSN). They exist so the
detector and the talk track have a realistic document to work on.
"""

from __future__ import annotations

COMPANY = "Lakeside Auto Group"
STORE = "Lakeside Honda"

# Fictional values used by tests that assert "raw PII never appears in the
# model input or the audit log." Keep this list in sync with the sample text.
SAMPLE_PII = {
    "name": "Maya Elena Alvarez",
    "ssn": "219-09-9999",
    "dob": "03/14/1988",
    "drivers_license": "FL1234567",
    "phone": "(207) 555-0148",
    "email": "maya.alvarez@example.com",
    "credit_card": "4111-1111-1111-1111",
    "vin": "1LKSDM26XMCB00001",
    "routing_number": "267084005",
    "bank_account": "1002003344",
}

CREDIT_APP = f"""Lakeside Auto Group — F&I credit application review
Store: Lakeside Honda    Desk: afternoon shift    Date: 2026-11-24

Please draft a short desk-manager review of this credit application before we send it to the lender. Quote the identifiers so I can check them against the deal jacket.

Applicant name: {SAMPLE_PII['name']}
SSN: {SAMPLE_PII['ssn']}
Date of birth: {SAMPLE_PII['dob']}
Driver's license: {SAMPLE_PII['drivers_license']}
Phone: {SAMPLE_PII['phone']}
Email: {SAMPLE_PII['email']}

Vehicle: 2023 Honda CR-V EX    VIN: {SAMPLE_PII['vin']}
Selling price: $32,450    Down payment: $2,500
Requested term: 72 months    Target APR: 6.49%

Bank for ACH down-payment residual:
Routing number: {SAMPLE_PII['routing_number']}
Account number: {SAMPLE_PII['bank_account']}

A deposit was authorized on the customer's Visa {SAMPLE_PII['credit_card']}. Confirm the last four in your review and flag anything the desk should double-check before submission.

These values are fictional sample data for a portfolio demo.
"""

NO_PII = """Lakeside Auto Group — process question

What documents usually sit in a deal jacket before we submit a credit application to the lender? I do not have a specific customer in front of me; this is a process question only.
"""

PARTIAL = f"""Quick follow-up from Lakeside Honda F&I.

Can you confirm we have a callback number for the buyer at {SAMPLE_PII['phone']} and that the email on the recap is {SAMPLE_PII['email']}? No other application details in this note.
"""

SAMPLES = {
    "credit_application": {
        "title": "F&I credit application",
        "blurb": "A full Lakeside Honda credit app: name, SSN, DOB, license, phone, email, VIN, bank routing and account, and a test Visa.",
        "prompt": CREDIT_APP.strip() + "\n",
        "actor": "jordan.lee",
        "role": "fi_manager",
    },
    "callback_only": {
        "title": "Callback and email only",
        "blurb": "A short follow-up with just a phone number and email — useful to show the same values get the same tokens.",
        "prompt": PARTIAL.strip() + "\n",
        "actor": "jordan.lee",
        "role": "fi_manager",
    },
    "process_question": {
        "title": "Process question (no PII)",
        "blurb": "A deal-jacket process question with no personal data, so the model input and the original should match.",
        "prompt": NO_PII.strip() + "\n",
        "actor": "jordan.lee",
        "role": "fi_manager",
    },
}


def list_samples() -> list[dict]:
    return [
        {"id": key, "title": value["title"], "blurb": value["blurb"]}
        for key, value in SAMPLES.items()
    ]


def get_sample(sample_id: str) -> dict:
    return SAMPLES[sample_id]


def all_raw_values() -> list[str]:
    return list(SAMPLE_PII.values())
