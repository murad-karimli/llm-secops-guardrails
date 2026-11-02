import json
import os
import re
from langchain_core.tools import tool

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "secret_db.json")

RESTRICTED_FIELDS = {"salary", "api_key"}

INDIRECT_INJECTION_PATTERNS = [
    re.compile(r"\[INTERNAL PROCESSING DIRECTIVE\].*?\[END DIRECTIVE\]", re.IGNORECASE | re.DOTALL),
    re.compile(r"<div[^>]*style=[\"'][^\"']*(?:font-size:\s*0|color:\s*transparent|display:\s*none)[^\"']*[\"'][^>]*>.*?</div>", re.IGNORECASE | re.DOTALL),
    re.compile(r"SYSTEM INSTRUCTION:.*", re.IGNORECASE)
]

def _load_db() -> dict:
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

@tool
def query_employee_db_vulnerable(username: str) -> str:
    """Queries the employee database and returns the full raw JSON record for a given username."""
    db = _load_db().get("employees", {})
    user_record = db.get(username.lower())
    if not user_record:
        return json.dumps({"error": "Employee not found"})
    return json.dumps(user_record)

@tool
def query_employee_db_secure(username: str) -> str:
    """Queries the employee database and returns only public profile attributes for a given username."""
    db = _load_db().get("employees", {})
    user_record = db.get(username.lower())
    if not user_record:
        return json.dumps({"error": "Employee not found"})
    
    sanitized_record = {
        k: v for k, v in user_record.items() if k not in RESTRICTED_FIELDS
    }
    return json.dumps(sanitized_record)

@tool
def read_kb_article_vulnerable(topic: str) -> str:
    """Reads an internal knowledge base article by topic ('password_reset' or 'cloud_spend') and returns raw content."""
    kb = _load_db().get("kb_articles", {})
    article = kb.get(topic.lower())
    if not article:
        return json.dumps({"error": f"Article '{topic}' not found. Available topics: password_reset, cloud_spend"})
    return json.dumps(article)

@tool
def read_kb_article_secure(topic: str) -> str:
    """Reads an internal knowledge base article by topic ('password_reset' or 'cloud_spend') with sanitization against indirect prompt injection."""
    kb = _load_db().get("kb_articles", {})
    article = kb.get(topic.lower())
    if not article:
        return json.dumps({"error": f"Article '{topic}' not found. Available topics: password_reset, cloud_spend"})
    
    sanitized_article = dict(article)
    content = sanitized_article.get("content", "")
    
    for pattern in INDIRECT_INJECTION_PATTERNS:
        content = pattern.sub("[SANITIZED_INDIRECT_PAYLOAD_REMOVED]", content)
        
    sanitized_article["content"] = content
    return json.dumps(sanitized_article)