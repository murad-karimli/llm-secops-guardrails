import re

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]

INGRESS_BLACKLIST = [
    "ignore all previous",
    "system override",
    "emergency protocol",
    "/override_admin_mode"
]

EGRESS_PATTERNS = [
    re.compile(r"sk-secret-[a-zA-Z0-9_-]+", re.IGNORECASE),
    re.compile(r'"salary":\s*\d+', re.IGNORECASE),
    re.compile(r"\$\d{2,3},\d{3}", re.IGNORECASE),
    re.compile(r"http://192\.168\.\d+\.\d+:\d+/reset", re.IGNORECASE)
]

def detect_zero_width(text: str) -> bool:
    """Detects presence of invisible zero-width Unicode characters."""
    return any(zw in text for zw in ZERO_WIDTH_CHARS)

def normalize_text(text: str) -> str:
    """Strips zero-width characters and collapses single-character spacing (e.g. 's k - s e c r e t')."""
    cleaned = text
    for zw in ZERO_WIDTH_CHARS:
        cleaned = cleaned.replace(zw, "")
    collapsed = re.sub(r"(?<=\b\w)\s+(?=\w\b)", "", cleaned)
    collapsed = re.sub(r"\s*-\s*", "-", collapsed)
    return collapsed

def inspect_ingress(prompt: str, phase: int = 2) -> tuple[bool, str, str]:
    """
    Checks incoming user prompt against static signature blacklist.
    Returns: (allowed, status_reason, mitre_atlas_id)
    """
    if phase >= 3 and detect_zero_width(prompt):
        return False, "Blocked: Zero-Width Unicode obfuscation detected (U+200B/U+200C)", "AML.T0043 (Craft Adversarial Data)"

    target_text = normalize_text(prompt).lower() if phase >= 3 else prompt.lower()

    for signature in INGRESS_BLACKLIST:
        if signature in target_text:
            return False, f"Blocked by Ingress Filter: Matched signature '{signature}'", "AML.T0051.000 (Direct Prompt Injection)"
    return True, "Passed", "None"

def inspect_egress(response_text: str, phase: int = 2) -> tuple[bool, str, str]:
    """
    Scans outbound LLM response for sensitive credential, salary, or phishing leaks.
    Phase 2 scans raw text only (vulnerable to character spacing).
    Phase 3 normalizes and collapses spaced characters before scanning.
    """
    for pattern in EGRESS_PATTERNS:
        if pattern.search(response_text):
            return False, f"Blocked by Egress DLP: Pattern '{pattern.pattern}' detected", "AML.T0024 (Exfiltration via Inference API)"

    if phase >= 3:
        normalized_response = normalize_text(response_text)
        for pattern in EGRESS_PATTERNS:
            if pattern.search(normalized_response):
                return False, f"Blocked by Normalized Egress DLP: De-obfuscated pattern '{pattern.pattern}' caught!", "AML.T0024 (Obfuscated Exfiltration Bypass Blocked)"

    return True, "Passed", "None"