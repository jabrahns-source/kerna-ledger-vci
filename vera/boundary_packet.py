#!/usr/bin/env python3
"""
Organizational Boundary Packet
Sealed, signed, hashable record of the chosen GHG Protocol consolidation approach
and the set of obligated entities.

This is a first-class evidence artifact for both the reporting entity and any
future assurance provider.
"""

from __future__ import annotations

import json
import time
import uuid
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from kerna_ledger_hash import attach_content_hash, verify_content_hash


VALID_APPROACHES = {"equity_share", "financial_control", "operational_control"}


def canonicalize_jcs(obj: Any) -> bytes:
    """Strict JCS-style canonicalization (sorted keys, no whitespace)."""
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
    elif isinstance(obj, float):
        # Boundary packets must not contain floats in the sealed surface
        raise TypeError("Floating-point values are not permitted in boundary packets")
    else:
        raise TypeError(f"Unsupported type in JCS: {type(obj)}")


class BoundaryPacketBuilder:
    """Constructs a sealed Organizational Boundary Packet."""

    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

    def build(
        self,
        approach: str,
        obligated_entities: List[Dict[str, Any]],
        exclusions: Optional[List[str]] = None,
        reporting_entity_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a sealed boundary packet.

        Parameters
        ----------
        approach : str
            One of "equity_share", "financial_control", "operational_control".
        obligated_entities : list of dict
            Each dict should contain at least:
              - "name" (str)
              - "id" (str, optional but recommended)
              - "equity_percent" (int, 0-10000 for basis points, only required for equity_share)
        exclusions : list of str, optional
            Explicit statements of what is excluded from the boundary.
        reporting_entity_id : str, optional
            Identifier of the reporting entity making the decision.
        notes : str, optional
            Free-text rationale (kept short; does not affect the hash of core fields).
        """
        if approach not in VALID_APPROACHES:
            raise ValueError(f"approach must be one of {sorted(VALID_APPROACHES)}")

        # Normalize equity percentages to integer basis points (0-10000) to keep the surface integer-only
        normalized_entities = []
        for ent in obligated_entities:
            e = deepcopy(ent)
            if approach == "equity_share":
                if "equity_percent" not in e:
                    raise ValueError("equity_share approach requires equity_percent on every entity")
                pct = e["equity_percent"]
                if isinstance(pct, float):
                    # Convert percentage to basis points
                    e["equity_percent_bp"] = int(round(pct * 100))
                    del e["equity_percent"]
                elif isinstance(pct, int):
                    # Assume already basis points if > 100, otherwise treat as percent
                    if pct <= 100:
                        e["equity_percent_bp"] = pct * 100
                    else:
                        e["equity_percent_bp"] = pct
                    if "equity_percent" in e:
                        del e["equity_percent"]
                else:
                    raise TypeError("equity_percent must be int or float")
            normalized_entities.append(e)

        packet: Dict[str, Any] = {
            "v": 1,
            "type": "organizational_boundary",
            "id": f"urn:uuid:{uuid.uuid4()}",
            "ts": int(time.time()),
            "reporting_entity_id": reporting_entity_id or "",
            "payload": {
                "approach": approach,
                "obligated_entities": normalized_entities,
                "exclusions": exclusions or [],
                "notes": notes or "",
            },
        }

        # Sign the canonical form (excluding the signature block itself)
        canonical = canonicalize_jcs(packet)
        signature = self.private_key.sign(canonical)

        packet["sig_edge"] = {
            "algo": "Ed25519",
            "pub": self.public_key_hex(),
            "val": signature.hex(),
        }

        # Attach content hash (self-referential field excluded)
        attach_content_hash(packet, exclude_key="ledger_hash")

        return packet


def verify_boundary_packet(packet: Dict[str, Any], expected_pub_hex: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Clean-room verification of an Organizational Boundary Packet.
    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []

    if not isinstance(packet, dict):
        return False, ["Packet must be a dict"]

    if packet.get("type") != "organizational_boundary":
        errors.append("type must be 'organizational_boundary'")

    payload = packet.get("payload")
    if not isinstance(payload, dict):
        errors.append("payload missing or not a dict")
        return False, errors

    approach = payload.get("approach")
    if approach not in VALID_APPROACHES:
        errors.append(f"invalid approach: {approach!r}")

    entities = payload.get("obligated_entities")
    if not isinstance(entities, list):
        errors.append("obligated_entities must be a list")
    else:
        for i, ent in enumerate(entities):
            if not isinstance(ent, dict):
                errors.append(f"entity[{i}] is not a dict")
                continue
            if "name" not in ent:
                errors.append(f"entity[{i}] missing 'name'")
            if approach == "equity_share" and "equity_percent_bp" not in ent:
                errors.append(f"entity[{i}] missing equity_percent_bp under equity_share")

    # Signature check
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

    # Content hash
    if not verify_content_hash(packet, exclude_key="ledger_hash"):
        errors.append("ledger_hash mismatch")

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Minimal self-test when run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    builder = BoundaryPacketBuilder()
    pkt = builder.build(
        approach="operational_control",
        obligated_entities=[
            {"name": "Facility Alpha", "id": "FAC-001"},
            {"name": "Facility Beta", "id": "FAC-002"},
        ],
        exclusions=["Leased office space under operating lease (Scope 3 candidate)"],
        reporting_entity_id="EXAMPLE-CORP",
        notes="Operational control approach selected to align with internal management reporting.",
    )
    print("Boundary packet created.")
    print(json.dumps(pkt, indent=2)[:600], "...")
    ok, errs = verify_boundary_packet(pkt, expected_pub_hex=builder.public_key_hex())
    print("Verification:", "PASS" if ok else "FAIL", errs)
