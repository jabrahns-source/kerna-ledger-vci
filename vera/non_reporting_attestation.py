#!/usr/bin/env python3
"""
Non-Reporting Attestation Packet

Sealed artifact for the limited first-year (2026) path under CARB guidance:
entities that were neither possessing nor collecting Scope 1 and Scope 2
emissions data as of December 5, 2024 may submit a statement of non-reporting.

This packet records that statement in a cryptographically verifiable form
so the decision itself becomes part of the immutable evidence surface.
It is valid only for the 2026 reporting cycle.
"""

from __future__ import annotations

import json
import time
import uuid
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from kerna_ledger_hash import attach_content_hash, verify_content_hash


DEC_5_2024_EPOCH = 1733366400  # 2024-12-05 00:00:00 UTC (approximate anchor)


def canonicalize_jcs(obj: Any) -> bytes:
    if isinstance(obj, dict):
        pairs = []
        for k in sorted(obj.keys()):
            if not isinstance(k, str):
                raise TypeError("JSON keys must be strings")
            val = canonicalize_jcs(obj[k]).decode("utf-8")
            pairs.append(f'"{k}":{val}')
        return ("{" + ",".join(pairs) + "}").encode("utf-8")
    elif isinstance(obj, list):
        items = [canonicalize_jcs(item).decode("utf-8") for item in obj]
        return ("[" + ",".join(items) + "]").encode("utf-8")
    elif isinstance(obj, str):
        escaped = (obj.replace("\\", "\\\\")
                      .replace('"', '\\"')
                      .replace("\b", "\\b")
                      .replace("\f", "\\f")
                      .replace("\n", "\\n")
                      .replace("\r", "\\r")
                      .replace("\t", "\\t"))
        return f'"{escaped}"'.encode("utf-8")
    elif isinstance(obj, bool):
        return b"true" if obj else b"false"
    elif obj is None:
        return b"null"
    elif isinstance(obj, int):
        return str(obj).encode("utf-8")
    else:
        raise TypeError(f"Unsupported type in JCS: {type(obj)}")


class NonReportingAttestationBuilder:
    """Constructs a sealed Non-Reporting Attestation Packet for the 2026 cycle."""

    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

    def build(
        self,
        reporting_entity_id: str,
        reporting_entity_legal_name: str,
        authorized_signatory_name: str,
        authorized_signatory_title: str,
        statement: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a sealed non-reporting attestation.

        The core assertion is that, as of December 5, 2024, the entity
        was neither possessing nor collecting Scope 1 and Scope 2
        emissions data (and was not planning to collect such data at that time).
        """
        default_statement = (
            "As of December 5, 2024, the reporting entity was neither possessing "
            "nor collecting Scope 1 and Scope 2 greenhouse gas emissions data, "
            "nor was it planning to collect such data at that time. "
            "This attestation is made solely for the 2026 reporting cycle under "
            "CARB's first-year guidance and the Initial Regulation."
        )

        packet: Dict[str, Any] = {
            "v": 1,
            "type": "non_reporting_attestation",
            "id": f"urn:uuid:{uuid.uuid4()}",
            "ts": int(time.time()),
            "reporting_cycle": 2026,
            "anchor_date": "2024-12-05",
            "payload": {
                "reporting_entity_id": reporting_entity_id,
                "reporting_entity_legal_name": reporting_entity_legal_name,
                "authorized_signatory_name": authorized_signatory_name,
                "authorized_signatory_title": authorized_signatory_title,
                "statement": statement or default_statement,
                "scopes_covered": [1, 2],
                "valid_for_cycle_only": 2026,
            },
        }

        canonical = canonicalize_jcs(packet)
        signature = self.private_key.sign(canonical)

        packet["sig_edge"] = {
            "algo": "Ed25519",
            "pub": self.public_key_hex(),
            "val": signature.hex(),
        }

        attach_content_hash(packet, exclude_key="ledger_hash")
        return packet


def verify_non_reporting_attestation(
    packet: Dict[str, Any],
    expected_pub_hex: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """Clean-room verification of a Non-Reporting Attestation Packet."""
    errors: List[str] = []

    if not isinstance(packet, dict):
        return False, ["Packet must be a dict"]

    if packet.get("type") != "non_reporting_attestation":
        errors.append("type must be 'non_reporting_attestation'")

    if packet.get("reporting_cycle") != 2026:
        errors.append("reporting_cycle must be 2026")

    payload = packet.get("payload")
    if not isinstance(payload, dict):
        errors.append("payload missing or not a dict")
        return False, errors

    required = [
        "reporting_entity_id",
        "reporting_entity_legal_name",
        "authorized_signatory_name",
        "authorized_signatory_title",
        "statement",
    ]
    for field in required:
        if not payload.get(field):
            errors.append(f"missing or empty payload field: {field}")

    if payload.get("valid_for_cycle_only") != 2026:
        errors.append("valid_for_cycle_only must be 2026")

    # Signature
    working = deepcopy(packet)
    sig_block = working.pop("sig_edge", None)
    if not sig_block:
        errors.append("missing sig_edge")
    else:
        pub_hex = sig_block.get("pub")
        sig_hex = sig_block.get("val")
        if expected_pub_hex and pub_hex != expected_pub_hex:
            errors.append("public key does not match expected")
        try:
            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            canonical = canonicalize_jcs(working)
            public_key.verify(sig_bytes, canonical)
        except Exception as e:
            errors.append(f"signature verification failed: {e}")

    if not verify_content_hash(packet, exclude_key="ledger_hash"):
        errors.append("ledger_hash mismatch")

    return len(errors) == 0, errors


if __name__ == "__main__":
    builder = NonReportingAttestationBuilder()
    pkt = builder.build(
        reporting_entity_id="EXAMPLE-CORP-001",
        reporting_entity_legal_name="Example Corporation",
        authorized_signatory_name="Jane Doe",
        authorized_signatory_title="Chief Sustainability Officer",
    )
    print("Non-reporting attestation packet created.")
    print(json.dumps(pkt, indent=2)[:700], "...")
    ok, errs = verify_non_reporting_attestation(pkt, expected_pub_hex=builder.public_key_hex())
    print("Verification:", "PASS" if ok else "FAIL", errs)
