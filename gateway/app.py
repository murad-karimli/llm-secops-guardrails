import os
import sys
import requests
from flask import Flask, request, jsonify, render_template

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),"..")))

from agent.core import SecureAgentEngine
from gateway.filter_rules import inspect_ingress, inspect_egress

app = Flask(__name__)
agent_engine = SecureAgentEngine()

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/secops/gateway")

def evaluate_opa_policy(prompt: str) -> dict:
    """Queries Open Policy Agent (OPA) for dynamic risk scoring and decision."""
    try:
        response = requests.post(OPA_URL, json={"input": {"prompt": prompt}}, timeout=5)
        if response.status_code == 200:
            return response.json().get("result", {})
        return {"allow": False, "risk_score": 100, "block_reasons": ["OPA server returned non-200 status"]}
    except Exception as e:
        return {"allow": False, "risk_score": 100, "block_reasons": [f"OPA connection error: {str(e)}"]}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.json
    user_prompt = data.get("prompt", "").strip()
    phase = int(data.get("phase", 0))

    telemetry = {
        "phase": phase,
        "ingress_status": "Bypassed",
        "opa_status": "Bypassed",
        "opa_risk_score": 0,
        "tool_calls": [],
        "egress_status": "Bypassed",
        "blocked": False
    }

    if phase >= 2:
        allowed, reason = inspect_ingress(user_prompt)
        telemetry["ingress_status"] = reason
        if not allowed:
            telemetry["blocked"] = True
            return jsonify({
                "reply": f"[GATEWAY INGRESS BLOCK] {reason}",
                "telemetry": telemetry
            })

    if phase == 3:
        opa_result = evaluate_opa_policy(user_prompt)
        allowed = opa_result.get("allow", False)
        risk_score = opa_result.get("risk_score", 0)
        reasons = opa_result.get("block_reasons", [])

        telemetry["opa_risk_score"] = risk_score
        if not allowed:
            reason_str = "; ".join(reasons) if reasons else "Risk threshold exceeded"
            telemetry["opa_status"] = f"Denied (Score: {risk_score}) - {reason_str}"
            telemetry["blocked"] = True
            return jsonify({
                "reply": f"[OPA POLICY INTERVENTION] Request denied. Risk Score: {risk_score}. Reasons: {reason_str}",
                "telemetry": telemetry
            })
        telemetry["opa_status"] = f"Allowed (Score: {risk_score})"

    agent_result = agent_engine.execute(user_prompt, phase=phase)
    reply_text = agent_result["reply"]
    telemetry["tool_calls"] = agent_result["tool_calls"]

    if phase >= 2:
        allowed, reason = inspect_egress(reply_text)
        telemetry["egress_status"] = reason
        if not allowed:
            telemetry["blocked"] = True
            return jsonify({
                "reply": f"[GATEWAY EGRESS DLP BLOCK] {reason}",
                "telemetry": telemetry
            })

    return jsonify({
        "reply": reply_text,
        "telemetry": telemetry
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)