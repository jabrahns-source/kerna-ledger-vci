#!/usr/bin/env python3
"""
Kerna-Ledger Hashing — canonical content hash excluding self-referential hash/proof field.

Single source of truth. Use compute_content_hash(packet, exclude_key="merkle_proof") for VERA packets.
"""

import json
import hashlib
from copy import deepcopy
from typing import Any, Dict


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> str:
    """
    Compute SHA-256 over packet, deliberately excluding the given key from its own preimage.

    Prevents the self-referential hash bug. Content fields (node_verification, sig_*, payload) stay in.
    """
    if not isinstance(packet, dict):
        raise TypeError("packet must be a dict")

    to_hash = deepcopy(packet)
    to_hash.pop(exclude_key, None)

    canonical = _canonical_json(to_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_ledger_hash(packet: Dict[str, Any]) -> str:
    return compute_content_hash(packet, exclude_key="ledger_hash")


def attach_ledger_hash(packet: Dict[str, Any]) -> Dict[str, Any]:
    packet["ledger_hash"] = compute_ledger_hash(packet)
    return packet


def verify_ledger_hash(packet: Dict[str, Any]) -> bool:
    if not isinstance(packet, dict) or "ledger_hash" not in packet:
        return False
    stored = packet["ledger_hash"]
    if not isinstance(stored, str) or len(stored) != 64:
        return False
    return stored == compute_ledger_hash(packet)


def attach_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> Dict[str, Any]:
    packet[exclude_key] = compute_content_hash(packet, exclude_key=exclude_key)
    return packet


def verify_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> bool:
    if not isinstance(packet, dict) or exclude_key not in packet:
        return False
    stored = packet[exclude_key]
    if not isinstance(stored, str) or len(stored) != 64:
        return False
    return stored == compute_content_hash(packet, exclude_key=exclude_key)


if __name__ == "__main__":
    # ledger_hash example
    p1 = {"id": "t1", "payload": {"emissions_scaled": 123456}, "node_verification": {"sig": ".."}}
    attach_ledger_hash(p1)
    print("ledger verify:", verify_ledger_hash(p1))

    # merkle_proof example (VERA style)
    p2 = {"v": 3, "payload": {"emissions_scaled": 10000}, "sig_edge": {"pub": ".."}}
    attach_content_hash(p2, exclude_key="merkle_proof")
    print("merkle_proof verify:", verify_content_hash(p2, exclude_key="merkle_proof"))