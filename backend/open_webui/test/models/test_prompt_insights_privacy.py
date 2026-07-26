import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.prompt_insights.pii_scrubber import (
    anonymize_user_id,
    hash_scrubbed_text,
    scrub_pii,
)


def test_scrub_pii_replaces_email_phone_url_iban():
    raw = "mario.rossi@example.com +39 347 123 4567 https://foo.test IT60X0542811101000000123456"
    cleaned, had_pii = scrub_pii(raw)

    assert had_pii is True
    assert "[EMAIL]" in cleaned
    assert "[PHONE]" in cleaned
    assert "[URL]" in cleaned
    assert "[IBAN]" in cleaned


def test_scrub_pii_does_not_scrub_short_tokens():
    raw = "Use api_key=abc123 for testing"
    cleaned, had_pii = scrub_pii(raw)

    assert had_pii is False
    assert cleaned == raw


def test_scrub_pii_does_not_scrub_luhn_failing_card_numbers():
    raw = "Card number 4111111111111"
    cleaned, had_pii = scrub_pii(raw)

    assert had_pii is False
    assert cleaned == raw


def test_hmac_changes_with_secret():
    assert anonymize_user_id("u1", "secret-a") != anonymize_user_id("u1", "secret-b")


def test_hash_scrubbed_text_uses_scrubbed_text():
    raw = "Contact me at mario.rossi@example.com"
    scrubbed, had_pii = scrub_pii(raw)

    assert had_pii is True
    assert hash_scrubbed_text(raw) == hash_scrubbed_text(scrubbed)
