import re

# Rule lists
URGENT_WORDS = ["urgent", "verify", "immediately", "suspended", "act now", "limited time", "confirm"]
CREDENTIAL_WORDS = ["password", "otp", "pin", "credit card", "bank", "login", "ssn"]
URL_SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]

def detect_phishing(input_text):
    score = 0
    triggered_rules = []

    text_lower = input_text.lower()

    # Urgent words
    for word in URGENT_WORDS:
        if word in text_lower:
            score += 2
            triggered_rules.append(f"Urgent word detected: '{word}'")

    # Credential request words
    for word in CREDENTIAL_WORDS:
        if word in text_lower:
            score += 3
            triggered_rules.append(f"Credential request detected: '{word}'")

    # URL shorteners
    for shortener in URL_SHORTENERS:
        if shortener in text_lower:
            score += 3
            triggered_rules.append(f"URL shortener detected: '{shortener}'")

    # Suspicious IP URL
    ip_pattern = r"http[s]?://\d+\.\d+\.\d+\.\d+"
    if re.search(ip_pattern, text_lower):
        score += 4
        triggered_rules.append("IP address used instead of domain")

    # Risk level
    if score >= 8:
        risk = "HIGH"
    elif score >= 4:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {"risk_level": risk, "risk_score": score, "triggered_rules": triggered_rules}
