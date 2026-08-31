#!/usr/bin/env python3
"""Canonical content-hash tests. Hash must ignore the self-referential field."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kerna_ledger_hash import (  # noqa: E402
    attach_ledger_hash,
    compute_ledger_hash,
    verify_ledger_hash,
)


def test_key_order_does_not_change_hash() -> None:
    a = {"facility": "CAISO-1", "tco2e": 12, "interval": "2026-Q2"}
    b = {"interval": "2026-Q2", "tco2e": 12, "facility": "CAISO-1"}
    assert compute_ledger_hash(a) == compute_ledger_hash(b)


def test_attach_and_verify() -> None:
    packet = {"facility": "CAISO-1", "tco2e": 12}
    attach_ledger_hash(packet)
    assert "ledger_hash" in packet
    assert len(packet["ledger_hash"]) == 64
    assert verify_ledger_hash(packet) is True


def test_tamper_fails_verify() -> None:
    packet = {"facility": "CAISO-1", "tco2e": 12}
    attach_ledger_hash(packet)
    packet["tco2e"] = 13
    assert verify_ledger_hash(packet) is False


def test_hash_excludes_self_field() -> None:
    packet = {"facility": "CAISO-1", "ledger_hash": "deadbeef" * 8}
    h1 = compute_ledger_hash(packet)
    packet["ledger_hash"] = "cafed00d" * 8
    h2 = compute_ledger_hash(packet)
    assert h1 == h2
