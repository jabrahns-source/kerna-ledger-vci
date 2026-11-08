#!/usr/bin/env python3
"""Tests for Non-Reporting Attestation Packet."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vera.non_reporting_attestation import (  # noqa: E402
    NonReportingAttestationBuilder,
    verify_non_reporting_attestation,
)


def test_attestation_roundtrip() -> None:
    builder = NonReportingAttestationBuilder()
    pkt = builder.build(
        reporting_entity_id="ENT-9",
        reporting_entity_legal_name="Example Holdings LLC",
        authorized_signatory_name="Alex Rivera",
        authorized_signatory_title="VP, Environmental Compliance",
    )
    assert pkt["type"] == "non_reporting_attestation"
    assert pkt["reporting_cycle"] == 2026
    assert pkt["payload"]["valid_for_cycle_only"] == 2026
    ok, errs = verify_non_reporting_attestation(pkt, expected_pub_hex=builder.public_key_hex())
    assert ok, errs


def test_missing_required_field_fails() -> None:
    builder = NonReportingAttestationBuilder()
    pkt = builder.build(
        reporting_entity_id="ENT-9",
        reporting_entity_legal_name="Example Holdings LLC",
        authorized_signatory_name="Alex Rivera",
        authorized_signatory_title="VP, Environmental Compliance",
    )
    del pkt["payload"]["authorized_signatory_title"]
    ok, errs = verify_non_reporting_attestation(pkt)
    assert not ok
    assert any("authorized_signatory_title" in e for e in errs)


def test_tamper_breaks_signature() -> None:
    builder = NonReportingAttestationBuilder()
    pkt = builder.build(
        reporting_entity_id="ENT-9",
        reporting_entity_legal_name="Example Holdings LLC",
        authorized_signatory_name="Alex Rivera",
        authorized_signatory_title="VP, Environmental Compliance",
    )
    pkt["payload"]["statement"] = "Altered statement after sealing"
    ok, errs = verify_non_reporting_attestation(pkt, expected_pub_hex=builder.public_key_hex())
    assert not ok
