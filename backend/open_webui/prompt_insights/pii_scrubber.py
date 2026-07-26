"""Privacy scrubbing helpers for prompt-insights analytics.

Covers common PII and secret-like values such as emails, phone numbers,
URLs, IBANs, fiscal codes, credit-card numbers, and token/secret values so
analytics payloads do not retain direct identifiers."""

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
    r"(?i)\b(?:api[_-]?key|access[_-]?token|bearer|secret|password|token)\b(?:\s*[:=]\s*|['\"])([A-Za-z0-9_\-./+=]{20,})"
)

PII_PATTERNS: list[tuple[Pattern[str], str]] = [
    (EMAIL_RE, "[EMAIL]"),
    (PHONE_RE, "[PHONE]"),
    (URL_RE, "[URL]"),
    (IBAN_RE, "[IBAN]"),
    (CF_RE, "[CF]"),
    (TOKEN_RE, "[TOKEN]"),
]


def _luhn_check(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 12:
        return False

    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - ord("0")
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def _replace_card_number(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARD]" if _luhn_check(digits) else match.group(0)


def _replace_phone_number(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if "+" in match.group(0) or len(digits) < 12:
        return "[PHONE]"
    return match.group(0)


def scrub_pii(text: str) -> tuple[str, bool]:
    if not text:
        return text, False

    cleaned_text = text
    had_pii = False

    for pattern, replacement in PII_PATTERNS:
        if pattern is PHONE_RE:
            new_text, count = pattern.subn(_replace_phone_number, cleaned_text)
        else:
            new_text, count = pattern.subn(replacement, cleaned_text)
        if count and new_text != cleaned_text:
            had_pii = True
            cleaned_text = new_text

    new_text, count = CARD_RE.subn(_replace_card_number, cleaned_text)
    if count and new_text != cleaned_text:
        had_pii = True
        cleaned_text = new_text

    return cleaned_text, had_pii


def anonymize_user_id(user_id: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


def hash_scrubbed_text(text: str) -> str:
    scrubbed_text, _ = scrub_pii(text)
    return hashlib.sha256(scrubbed_text.encode("utf-8")).hexdigest()
