#!/usr/bin/env python3
"""
schema_validation.py — Standalone ledger packet schema validator.
"""

import json
import sys
from typing import Any, Dict, List, Tuple


LEDGER_PACKET_SCHEMA_V1 = {
    "required_fields": {
        "packet_id": str,
        "timestamp": str,
        "node_id": str,
        "payload": dict,
        "node_verification": dict,
        "ledger_hash": str,
    },
    "optional_fields": {
        "previous_hash": str,
        "sequence": int,
        "metadata": dict,
    },
}

def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except Exception:
        return False

def validate_ledger_packet(packet: Dict[str, Any], schema: Dict[str, Any] = None) -> Tuple[bool, List[str]]:
    if schema is None:
        schema = LEDGER_PACKET_SCHEMA_V1
    errors: List[str] = []
    if not isinstance(packet, dict):
        return False, ["Packet must be a JSON object"]
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
                errors.append(f"ledger_hash must be 64 hex chars")
    is_valid = len(errors) == 0
    return is_valid, errors


def main():
    if len(sys.argv) > 1:
        # file validation
        pass
    else:
        print("schema_validation.py ready.")

if __name__ == "__main__":
    main()