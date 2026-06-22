#!/usr/bin/env python3
"""
Kerna-Ledger Hashing — canonical content hash excluding self-referential ledger_hash.

This fixes the pre-image inconsistency: ledger_hash is computed over the packet
*without* the ledger_hash field itself. node_verification (if present) *is* included
because it is part of the verifiable content.

Verification always strips ledger_hash before recomputing.
"""

import json
import hashlib
from copy import deepcopy
from typing import Any, Dict


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_ledger_hash(packet: Dict[str, Any]) -> str:
    """
    Compute SHA-256 content hash over the packet, *excluding* the 'ledger_hash' field.

    - If 'node_verification' is present, it participates in the hash (it's content).
    - The hash field itself is deliberately stripped so the stored hash can be
      independently verified without a circular dependency.
    """
    if not isinstance(packet, dict):
        raise TypeError("packet must be a dict")

    to_hash = deepcopy(packet)
    to_hash.pop("ledger_hash", None)

    canonical = _canonical_json(to_hash)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest


def attach_ledger_hash(packet: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a fresh correct ledger_hash (overwrites any stale one)."""
    packet["ledger_hash"] = compute_ledger_hash(packet)
    return packet


def verify_ledger_hash(packet: Dict[str, Any]) -> bool:
    """True iff stored ledger_hash matches canonical content hash (excluding itself)."""
    if not isinstance(packet, dict) or "ledger_hash" not in packet:
        return False
    stored = packet["ledger_hash"]
    if not isinstance(stored, str) or len(stored) != 64:
        return False
    return stored == compute_ledger_hash(packet)


if __name__ == "__main__":
    test_packet = {
        "packet_id": "test-001",
        "timestamp": "2026-06-21T19:30:00Z",
        "node_id": "denali-01",
        "payload": {"emissions_tco2e": 1234.56, "scope": 1},
        "node_verification": {
            "sig": "ed25519:abc123...",
            "pubkey": "ed25519:def456...",
            "timestamp": "2026-06-21T19:30:01Z"
        }
    }
    attach_ledger_hash(test_packet)
    print("Verification after attach:", verify_ledger_hash(test_packet))

    tampered = deepcopy(test_packet)
    tampered["payload"]["emissions_tco2e"] = 9999.99
    print("Tamper detection:", verify_ledger_hash(tampered))