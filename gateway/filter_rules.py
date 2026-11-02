import re

INGRESS_BLACKLIST = [
    "ignore all previous instructions",
    "system override",
    "emergency protocol",
    "/override_admin_mode"
]


EGRESS_PATTERNS = [
    re.compile(r"sk-secret-[a-zA-Z0-9_-]+", re.IGNORECASE),
    re.compile(r'"salary":\s*\d+', re.IGNORECASE),
    re.compile(r"\$\d{2,3},\d{3}", re.IGNORECASE)
]

def inspect_ingress(prompt: str) -> tuple[bool, str]:
    """Checks incoming user prompt against static signature blacklist."""
    lower_prompt = prompt.lower()
    for signature in INGRESS_BLACKLIST:
        if signature in lower_prompt:
            return False, f"Blocked by Ingress Filter: Matched signature '{signature}'"
    return True, "Passed"

def inspect_egress(response_text: str) -> tuple[bool, str]:
    """Scans outbound LLM response for sensitive credential or salary leaks."""
    for pattern in EGRESS_PATTERNS:
        if pattern.search(response_text):
            return False, f"Blocked by Egress DLP: Sensitive pattern '{pattern.pattern}' detected"
    return True, "Passed"