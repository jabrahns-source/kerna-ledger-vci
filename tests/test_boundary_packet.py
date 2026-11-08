#!/usr/bin/env python3
"""Tests for Organizational Boundary Packet."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vera.boundary_packet import (  # noqa: E402
    BoundaryPacketBuilder,
    verify_boundary_packet,
    VALID_APPROACHES,
)


def test_operational_control_roundtrip() -> None:
    builder = BoundaryPacketBuilder()
    pkt = builder.build(
        approach="operational_control",
        obligated_entities=[
            {"name": "Plant A", "id": "P-A"},
            {"name": "Plant B", "id": "P-B"},
        ],
        exclusions=["Third-party logistics under operating lease"],
        reporting_entity_id="TEST-001",
    )
    assert pkt["type"] == "organizational_boundary"
    assert pkt["payload"]["approach"] == "operational_control"
    ok, errs = verify_boundary_packet(pkt, expected_pub_hex=builder.public_key_hex())
    assert ok, errs


def test_equity_share_requires_percent() -> None:
    builder = BoundaryPacketBuilder()
    try:
        builder.build(
            approach="equity_share",
            obligated_entities=[{"name": "JV-1"}],  # missing equity_percent
        )
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_equity_share_normalizes_to_basis_points() -> None:
    builder = BoundaryPacketBuilder()
    pkt = builder.build(
        approach="equity_share",
        obligated_entities=[
            {"name": "JV-1", "equity_percent": 40},   # percent → 4000 bp
            {"name": "JV-2", "equity_percent": 2500}, # already bp
        ],
    )
    ents = pkt["payload"]["obligated_entities"]
    assert ents[0]["equity_percent_bp"] == 4000
    assert ents[1]["equity_percent_bp"] == 2500
    ok, errs = verify_boundary_packet(pkt, expected_pub_hex=builder.public_key_hex())
    assert ok, errs


def test_invalid_approach_rejected() -> None:
    builder = BoundaryPacketBuilder()
    try:
        builder.build(approach="something_else", obligated_entities=[])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_tamper_breaks_verification() -> None:
    builder = BoundaryPacketBuilder()
    pkt = builder.build(
        approach="financial_control",
        obligated_entities=[{"name": "Sub-1"}],
    )
    pkt["payload"]["approach"] = "equity_share"  # tamper after sealing
    ok, errs = verify_boundary_packet(pkt, expected_pub_hex=builder.public_key_hex())
    assert not ok
    assert any("signature" in e.lower() or "hash" in e.lower() for e in errs)
