import os
import sys
import requests
from flask import Flask, request, jsonify, render_template, make_response

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.core import SecureAgentEngine
from gateway.filter_rules import inspect_ingress, inspect_egress

app = Flask(__name__)
agent_engine = SecureAgentEngine()

OPA_URL = os.getenv("OPA_URL","http://localhost:8181/v1/data/secops/gateway")

def evaluate_opa_policy(prompt: str) -> dict:
    """Queries Open Policy Agent (OPA) for dynamic risk scoring and decision."""
    try:
        response = requests.post(OPA_URL, json={"input": {"prompt": prompt}}, timeout=5)
        if response.status_code == 200:
            return response.json().get("result", {})
        return {"allow": False,"risk_score": 100, "block_reasons": ["OPA server returned non-200 status"]}
    except Exception as e:
        return {"allow": False,"risk_score": 100, "block_reasons": [f"OPA connection error: {str(e)}"]}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Demonstrates M2.2.1 Passive/Active Reconnaissance surface.
    In Phase 0/1, leaks backend model, vector DB, and MCP configuration.
    In Phase 2/3, returns minimal hardened status.
    """
    phase = int(request.args.get("phase", 0))
    if phase <= 1:
        resp = make_response(jsonify({
            "status": "healthy",
            "service": "megacorp-piper-assistant",
            "version": "2.1.0-dev",
            "model": "llama3.2:latest (Ollama Local)",
            "context_window": 4096,
            "mcp_enabled": True,
            "exposed_tools": ["query_employee_db_vulnerable", "read_kb_article_vulnerable"]
        }))
        resp.headers["X-AI-Backend"] = "Ollama-Llama3.2"
        resp.headers["X-Orchestration"] = "LangChain-ReAct"
        return resp
    else:
        resp = make_response(jsonify({"status": "healthy"}))
        return resp

@app.route("/.well-known/agent.json", methods=["GET"])
def a2a_agent_card():
    """
    Demonstrates M4.2.3 A2A Agent Card Enumeration surface.
    """
    phase = int(request.args.get("phase", 0))
    if phase <= 1:
        return jsonify({
            "name": "Piper Operations & KB Agent",
            "description": "Internal HR/IT assistant with direct JSON database and KB read access",
            "protocolVersion": "0.2",
            "url": "http://localhost:8080",
            "capabilities": {"streaming": False, "mcp_tools": True},
            "skills": [
                {"id": "emp-lookup", "name": "Employee DB Lookup", "tags": ["hr", "salary", "api_key"]},
                {"id": "kb-reader", "name": "Knowledge Base Reader", "tags": ["rag", "policies"]}
            ],
            "securitySchemes": {}
        })
    else:
        return jsonify({
            "error": "Agent Card discovery requires mutual TLS or authorized bearer token in Hardened Mode."
        }), 401

@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.json
    user_prompt = data.get("prompt", "").strip()
    phase = int(data.get("phase", 0))

    telemetry = {
        "phase": phase,
        "mitre_atlas": "None (Benign Traffic)",
        "ingress_status": "Bypassed",
        "opa_status": "Bypassed",
        "opa_risk_score": 0,
        "tool_calls": [],
        "egress_status": "Bypassed",
        "blocked": False
    }

    if phase >= 2:
        allowed, reason, mitre_id = inspect_ingress(user_prompt, phase=phase)
        telemetry["ingress_status"] = reason
        if not allowed:
            telemetry["blocked"] = True
            telemetry["mitre_atlas"] = mitre_id
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
            telemetry["mitre_atlas"] = "AML.T0051.000 / AML.T0043 (OPA Policy Block)"
            return jsonify({
                "reply": f"[OPA POLICY INTERVENTION] Request denied. Risk Score: {risk_score}/50.\nReasons: {reason_str}",
                "telemetry": telemetry
            })
        telemetry["opa_status"] = f"Allowed (Score: {risk_score})"

    agent_result = agent_engine.execute(user_prompt, phase=phase)
    reply_text = agent_result["reply"]
    telemetry["tool_calls"] = agent_result["tool_calls"]

    for tc in telemetry["tool_calls"]:
        if "[SANITIZED_INDIRECT_PAYLOAD_REMOVED]" in tc.get("raw_output", ""):
            telemetry["mitre_atlas"] = "AML.T0051.001 / AML.T0020 (Indirect Poisoning Neutralized at Tool Layer)"

    if phase >= 2:
        allowed, reason, mitre_id = inspect_egress(reply_text, phase=phase)
        telemetry["egress_status"] = reason
        if not allowed:
            telemetry["blocked"] = True
            telemetry["mitre_atlas"] = mitre_id
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