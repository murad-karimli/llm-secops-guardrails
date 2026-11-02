import json
import os
from langchain_core.tools import tool

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "secret_db.json")
RESTRICTED_FIELDS = {"salary", "api_key"}

def _read_db():
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

@tool
def query_employee_db_vulnerable(username: str) -> str:
    """Query database and return raw employee record (Vulnerable Baseline)."""
    try:
        data = _read_db()
        username_clean = username.lower().strip()
        for record in data:
            if record.get("username", "").lower() == username_clean:
                return json.dumps(record, indent=2)
        return f"No employee found with username '{username}'."
    except Exception as e:
        return f"Database error: {str(e)}"

@tool
def query_employee_db_secure(username: str) -> str:
    """Query database and return sanitized employee record (Least Privilege)."""
    try:
        data = _read_db()
        username_clean = username.lower().strip()
        for record in data:
            if record.get("username", "").lower() == username_clean:
                sanitized_record = {
                    k: v for k, v in record.items() 
                    if k not in RESTRICTED_FIELDS
                }
                return json.dumps(sanitized_record, indent=2)
        return f"No employee found with username '{username}'."
    except Exception as e:
        return f"Database error: {str(e)}"