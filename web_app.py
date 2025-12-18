from flask import Flask, render_template, request
from rule_engine import detect_phishing
from virus_total import check_url_virustotal
import re

app = Flask(__name__)

# -------- URL Extraction --------
def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# -------- VirusTotal Wrapper (Optimized) --------
def virustotal_check_urls(urls):
    vt_results = []

    # 🚀 STEP 2 OPTIMIZATION: No URLs → Skip VirusTotal
    if not urls:
        return vt_results

    for url in urls:
        try:
            vt_stats = check_url_virustotal(url)

            if not vt_stats or "error" in vt_stats:
                vt_results.append({
                    "url": url,
                    "malicious": 0,
                    "status": "VT_ERROR"
                })
            else:
                vt_results.append({
                    "url": url,
                    "malicious": vt_stats.get("malicious", 0),
                    "status": "OK"
                })

        except Exception:
            vt_results.append({
                "url": url,
                "malicious": 0,
                "status": "EXCEPTION"
            })

    return vt_results

# -------- Final Risk Decision --------
def final_risk_decision(rule_result, vt_results):
    # VirusTotal has highest priority
    for vt in vt_results:
        if vt["status"] == "OK" and vt["malicious"] > 0:
            return "HIGH"

    # Rule engine fallback
    score = rule_result.get("risk_score", 0)
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"

# -------- Confidence Calculation --------
def calculate_confidence(rule_result, vt_results):
    rule_score = rule_result.get("risk_score", 0)

    # Rule Engine → max 70%
    rule_confidence = min((rule_score / 20) * 70, 70)

    # VirusTotal → max 30%
    vt_malicious = sum(vt.get("malicious", 0) for vt in vt_results)
    vt_confidence = min(vt_malicious * 10, 30)

    return int(rule_confidence + vt_confidence)

# -------- Explainability (WHY section) --------
def generate_explanation(rule_result, vt_results, final_risk):
    reasons = []

    if rule_result.get("triggered_rules"):
        reasons.append(
            "Rule Engine detected: " + ", ".join(rule_result["triggered_rules"])
        )

    for vt in vt_results:
        if vt.get("malicious", 0) > 0:
            reasons.append(
                f"VirusTotal flagged URL ({vt['url']}) as malicious"
            )

    reasons.append(f"Overall risk classified as {final_risk}")
    return reasons

# -------- Routes --------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        user_input = request.form.get("message", "")

        rule_result = detect_phishing(user_input)
        urls = extract_urls(user_input)

        # 🚀 VirusTotal runs ONLY if URLs exist
        vt_results = virustotal_check_urls(urls)

        final_risk = final_risk_decision(rule_result, vt_results)
        confidence = calculate_confidence(rule_result, vt_results)
        explanation = generate_explanation(rule_result, vt_results, final_risk)

        result = {
            "rule_result": rule_result,
            "vt_results": vt_results,
            "final_risk": final_risk,
            "confidence": confidence,
            "explanation": explanation
        }

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
