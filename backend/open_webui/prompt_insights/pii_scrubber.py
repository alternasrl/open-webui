import hashlib
import hmac
import re
from typing import Pattern


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]*)?(?:\(?\d{2,4}\)?[\s.-]*){2,5}\d{2,4}(?!\w)")
URL_RE = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)
IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b", re.IGNORECASE)
CF_RE = re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b", re.IGNORECASE)
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)")
TOKEN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|bearer|secret|password|token)\b(?:\s*[:=]\s*|['\"])([A-Za-z0-9_\-./+=]{4,})"
)

PII_PATTERNS: list[tuple[Pattern[str], str]] = [
    (EMAIL_RE, "[EMAIL]"),
    (PHONE_RE, "[PHONE]"),
    (URL_RE, "[URL]"),
    (IBAN_RE, "[IBAN]"),
    (CF_RE, "[CF]"),
    (CARD_RE, "[CARD]"),
    (TOKEN_RE, "[TOKEN]"),
]


def scrub_pii(text: str) -> tuple[str, bool]:
    if not text:
        return text, False

    cleaned_text = text
    had_pii = False

    for pattern, replacement in PII_PATTERNS:
        new_text, count = pattern.subn(replacement, cleaned_text)
        if count:
            had_pii = True
            cleaned_text = new_text

    return cleaned_text, had_pii


def anonymize_user_id(user_id: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def hash_scrubbed_text(text: str) -> str:
    scrubbed_text, _ = scrub_pii(text)
    return hashlib.sha256(scrubbed_text.encode("utf-8")).hexdigest()
