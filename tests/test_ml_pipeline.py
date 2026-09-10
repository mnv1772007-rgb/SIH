"""Regression coverage for fail-soft, offline ML corpus preparation."""

from __future__ import annotations

import json
from pathlib import Path

from AI_model.create_splits import stratified_group_split, verify_no_leakage
from AI_model.email_decoding import safe_decode_bytes
from AI_model.process_email_dataset import process_email_file
from AI_model.process_url_dataset import build_record, validate_and_normalize_url


def test_invalid_declared_charset_uses_general_fallbacks():
    decoded = safe_decode_bytes(b"hello \xff", "DEFAULT_CHARSET")

    assert decoded.text.startswith("hello")
    assert decoded.charset_used == "latin-1"
    assert "invalid_declared_charset" in decoded.warnings


def test_email_processor_handles_bad_charset_html_and_null_bytes(tmp_path: Path):
    message = tmp_path / "malformed-but-usable.eml"
    message.write_bytes(
        b"From: Sender <sender@example.test>\n"
        b"Subject: charset regression\n"
        b"MIME-Version: 1.0\n"
        b"Content-Type: text/html; charset=DEFAULT_CHARSET\n\n"
        b"<html><body>Hello \xff forensic pipeline\x00 <a href='https://example.test/a'>link</a></body></html>"
    )

    outcome = process_email_file(message, "benign", "benign")

    assert outcome.record is not None
    assert outcome.record.body
    assert outcome.record.metadata["has_html"] is True
    assert "invalid_declared_charset" in outcome.record.metadata["parse_warnings"]
    assert "\x00" not in outcome.record.text


def test_url_processor_is_static_and_rejects_invalid_schemes():
    normalized, error = validate_and_normalize_url("https://Example.TEST:443/a#fragment")
    assert (normalized, error) == ("https://example.test/a", None)
    assert validate_and_normalize_url("javascript:alert(1)")[1] == "invalid_scheme"
    record, error = build_record("https://example.test/a#fragment", "phishing", "fixture")
    assert error is None
    assert record is not None and record.metadata["offline_only"] is True
    assert record.fragment == ""


def test_group_aware_split_keeps_near_duplicate_group_together():
    records = [
        {"id": "a", "label": "benign", "text_hash": "a", "near_duplicate_group": "campaign-1"},
        {"id": "b", "label": "benign", "text_hash": "b", "near_duplicate_group": "campaign-1"},
        {"id": "c", "label": "benign", "text_hash": "c", "near_duplicate_group": "campaign-2"},
        {"id": "d", "label": "spam", "text_hash": "d", "near_duplicate_group": "campaign-3"},
        {"id": "e", "label": "spam", "text_hash": "e", "near_duplicate_group": "campaign-4"},
        {"id": "f", "label": "spam", "text_hash": "f", "near_duplicate_group": "campaign-5"},
    ]
    splits, _ = stratified_group_split(records, "email", 0.7, 0.15, 0.15)
    leakage = verify_no_leakage(splits, "email")
    locations = {split for split, items in splits.items() if any(item["id"] in {"a", "b"} for item in items)}

    assert leakage["leakage_free"] is True
    assert len(locations) == 1
