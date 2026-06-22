#!/usr/bin/env python3
"""
Kerna-Ledger Hashing — canonical content hash excluding self-referential field.
Generalized for any exclude_key.
"""

import json
import hashlib
from copy import deepcopy
from typing import Any, Dict


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> str:
    if not isinstance(packet, dict):
        raise TypeError("packet must be a dict")
    to_hash = deepcopy(packet)
    to_hash.pop(exclude_key, None)
    canonical = _canonical_json(to_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def attach_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> Dict[str, Any]:
    packet[exclude_key] = compute_content_hash(packet, exclude_key=exclude_key)
    return packet


def compute_ledger_hash(packet: Dict[str, Any]) -> str:
    return compute_content_hash(packet, exclude_key="ledger_hash")


def attach_ledger_hash(packet: Dict[str, Any]) -> Dict[str, Any]:
    return attach_content_hash(packet, exclude_key="ledger_hash")


def verify_content_hash(packet: Dict[str, Any], exclude_key: str = "ledger_hash") -> bool:
    if not isinstance(packet, dict) or exclude_key not in packet:
        return False
    stored = packet[exclude_key]
    if not isinstance(stored, str) or len(stored) != 64:
        return False
    return stored == compute_content_hash(packet, exclude_key=exclude_key)


def verify_ledger_hash(packet: Dict[str, Any]) -> bool:
    return verify_content_hash(packet, exclude_key="ledger_hash")