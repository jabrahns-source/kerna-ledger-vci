#!/usr/bin/env python3
"""
schema_validation.py — Standalone ledger packet schema validator for Kerna-Ledger / VERA Substrata.

This replaces the previous near-empty stub. It can be run directly or imported.

It performs structural + semantic validation without external deps (pure stdlib).

Usage:
    python schema_validation.py                    # runs built-in test vectors
    python schema_validation.py path/to/packet.json
"""

import json
import sys
from typing import Any, Dict, List, Tuple
from copy import deepcopy


# =============================================================================
# EXPECTED SCHEMA (versioned so we can evolve it)
# =============================================================================

LEDGER_PACKET_SCHEMA_V1 = {
    "required_fields": {
        "packet_id": str,
        "timestamp": str,           # ISO-8601 preferred
        "node_id": str,
        "payload": dict,
        "node_verification": dict,
        "ledger_hash": str,         # 64 hex chars
    },
    "optional_fields": {
        "previous_hash": str,
        "sequence": int,
        "metadata": dict,
    },
    "payload_requirements": {
        # Add domain-specific keys here as they stabilize
        "emissions_tco2e": (int, float),
        "scope": int,
    },
    "node_verification_requirements": {
        "sig": str,
        "pubkey": str,
        "timestamp": str,
    }
}


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def validate_ledger_packet(packet: Dict[str, Any], schema: Dict[str, Any] = None) -> Tuple[bool, List[str]]:
    """
    Validate a ledger packet against the schema.

    Returns:
        (is_valid, list_of_error_messages)
    """
    if schema is None:
        schema = LEDGER_PACKET_SCHEMA_V1

    errors: List[str] = []

    if not isinstance(packet, dict):
        return False, ["Packet must be a JSON object (dict)"]

    # 1. Required fields present and correct type
    for field, expected_type in schema["required_fields"].items():
        if field not in packet:
            errors.append(f"Missing required field: '{field}'")
            continue
        value = packet[field]
        if not isinstance(value, expected_type):
            errors.append(f"Field '{field}' has wrong type: expected {expected_type.__name__}, got {type(value).__name__}")
            continue

        if field == "ledger_hash":
            if len(value) != 64 or not _is_hex(value):
                errors.append(f"ledger_hash must be 64 lowercase hex characters, got: {value[:16]}... (len={len(value)})")

    # 2. node_verification internal structure
    if "node_verification" in packet:
        nv = packet["node_verification"]
        if not isinstance(nv, dict):
            errors.append("node_verification must be an object")
        else:
            for subfield, expected_type in schema["node_verification_requirements"].items():
                if subfield not in nv:
                    errors.append(f"node_verification missing required subfield: '{subfield}'")
                elif not isinstance(nv[subfield], expected_type):
                    errors.append(f"node_verification.{subfield} wrong type")

    # 3. Payload basic shape
    if "payload" in packet and isinstance(packet["payload"], dict):
        payload = packet["payload"]
        for key, expected_types in schema.get("payload_requirements", {}).items():
            if key in payload:
                if not isinstance(payload[key], expected_types):
                    errors.append(f"payload.{key} has wrong type: expected one of {expected_types}")

    # 4. Optional fields type checks
    for field, expected_type in schema.get("optional_fields", {}).items():
        if field in packet and not isinstance(packet[field], expected_type):
            errors.append(f"Optional field '{field}' has wrong type: expected {expected_type.__name__}")

    is_valid = len(errors) == 0
    return is_valid, errors


def validate_file(path: str) -> Tuple[bool, List[str]]:
    """Load JSON from file and validate."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            packet = json.load(f)
    except Exception as e:
        return False, [f"Failed to load {path}: {e}"]
    return validate_ledger_packet(packet)


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
        valid, errs = validate_file(path)
        if valid:
            print(f"✅ VALID: {path}")
            sys.exit(0)
        else:
            print(f"❌ INVALID: {path}")
            for e in errs:
                print(f"   - {e}")
            sys.exit(1)
    else:
        print("Running schema_validation.py self-tests...\n")

        good_packet = {
            "packet_id": "case-006-fixed",
            "timestamp": "2026-06-21T19:45:00Z",
            "node_id": "denali-02",
            "payload": {"emissions_tco2e": 42.0, "scope": 1},
            "node_verification": {
                "sig": "ed25519:deadbeef...",
                "pubkey": "ed25519:cafebabe...",
                "timestamp": "2026-06-21T19:45:01Z"
            },
            "ledger_hash": "a" * 64
        }

        valid, errs = validate_ledger_packet(good_packet)
        print("Good packet test:", "PASS" if valid else "FAIL")

        bad1 = {k: v for k, v in good_packet.items() if k != "ledger_hash"}
        valid, errs = validate_ledger_packet(bad1)
        print("Missing ledger_hash test:", "PASS (caught)" if not valid else "FAIL")

        bad2 = {
            "packet_id": "bad-hash-len",
            "timestamp": "2026-06-21T19:45:00Z",
            "node_id": "denali-02",
            "payload": {"emissions_tco2e": 42.0, "scope": 1},
            "node_verification": {"sig": "x", "pubkey": "y", "timestamp": "z"},
            "ledger_hash": "short"
        }
        valid, errs = validate_ledger_packet(bad2)
        print("Bad hash length test:", "PASS (caught)" if not valid else "FAIL")

        print("\n✅ schema_validation.py is now a real validator.")


if __name__ == "__main__":
    main()