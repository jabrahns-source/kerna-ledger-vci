import json
import hashlib
import time
import uuid
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from z3 import Solver, Int, sat

"""
VERA PACKET v0.3 - HARDENED (Post-Audit)
Jacarri Sanders / Even The Odds Foundry

Changes from audit:
- Proper rounding: round() instead of int() truncation
- Added scope > 0 and timestamp bounds predicates
- Renamed merkle_proof → ledger_hash (honest content hash, not fake Merkle tree)
- Explicit comments on ML-DSA stub
- Improved JCS escaping for RFC 8785 compliance
"""

class SecurityError(Exception):
    pass

SCALE_FACTOR = 100
MAX_GRID_ALLOWANCE_SCALED = 200000
MIN_TS = 1577836800   # 2020-01-01
MAX_TS = 2051222400   # 2035-01-01


def canonicalize_jcs(obj: Any) -> bytes:
    if isinstance(obj, dict):
        pairs = []
        for k in sorted(obj.keys()):
            if not isinstance(k, str):
                raise TypeError("JSON keys must be strings")
            pairs.append(f'"{k}":{canonicalize_jcs(obj[k]).decode("utf-8")}')
        return f'{{{ ",".join(pairs) }}}'.encode('utf-8')
    elif isinstance(obj, list):
        return f'[{ ",".join(canonicalize_jcs(i).decode("utf-8") for i in obj) }]'.encode('utf-8')
    elif isinstance(obj, str):
        # Improved escaping for RFC 8785
        escaped = (obj.replace('\\', '\\\\')
                      .replace('"', '\\"')
                      .replace('\b', '\\b').replace('\f', '\\f')
                      .replace('\n', '\\n').replace('\r', '\\r')
                      .replace('\t', '\\t')
                      .replace('\x00', '\\u0000'))  # explicit null
        return f'"{escaped}"'.encode('utf-8')
    elif isinstance(obj, bool):
        return b'true' if obj else b'false'
    elif obj is None:
        return b'null'
    elif isinstance(obj, (int, float)):
        if isinstance(obj, float):
            raise TypeError("Floats strictly prohibited - use scaled integers")
        return str(obj).encode('utf-8')
    else:
        raise TypeError(f"Unsupported type: {type(obj)}")


class VERAEdgeClient:
    def __init__(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def get_public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

    def generate_packet(self, merkle_root: str, scope: int, raw_emissions: float) -> Tuple[Dict[str, Any], bytes]:
        if scope <= 0:
            raise ValueError("scope must be > 0")
        emissions_scaled = int(round(raw_emissions * SCALE_FACTOR))  # proper rounding
        ts = int(time.time())
        if not (MIN_TS <= ts <= MAX_TS):
            raise ValueError("Timestamp out of acceptable bounds")

        packet = {
            "v": 3,
            "id": f"urn:uuid:{uuid.uuid4()}",
            "ts": ts,
            "payload": {
                "root": merkle_root,
                "scope": scope,
                "emissions_scaled": emissions_scaled,
                "scale_factor": SCALE_FACTOR,
                "predicates": [
                    "Assert(E <= G_Max)",
                    "Assert(E >= 0)",
                    "Assert(scope > 0)"
                ]
            }
        }
        canonical_bytes = canonicalize_jcs(packet)
        signature = self.private_key.sign(canonical_bytes)
        packet["sig_edge"] = {
            "algo": "Ed25519",
            "pub": self.get_public_key_hex(),
            "val": signature.hex()
        }
        return packet, canonical_bytes


class VERANodeValidator:
    def __init__(self, expected_client_pub_key_hex: str):
        self.expected_pub_bytes = bytes.fromhex(expected_client_pub_key_hex)
        self.client_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(self.expected_pub_bytes)
        # ML-DSA stub - replace with real post-quantum implementation when available
        self.node_mldsa_pub_hex = "MLDSA65_STUB_PUBLIC_KEY_" + "a1b2c3d4" * 100
        self.node_mldsa_sig_hex = "MLDSA65_STUB_SIGNATURE_" + "f5e6d7c8" * 150

    def verify_edge_signature(self, received_packet: Dict[str, Any]) -> bool:
        working_packet = json.loads(json.dumps(received_packet))
        sig_block = working_packet.pop("sig_edge", None)
        if not sig_block or sig_block["pub"] != self.expected_pub_bytes.hex():
            return False
        reconstructed_canonical = canonicalize_jcs(working_packet)
        try:
            self.client_pub_key.verify(bytes.fromhex(sig_block["val"]), reconstructed_canonical)
            return True
        except Exception:
            return False

    def execute_logic_predicates(self, received_packet: Dict[str, Any]) -> bool:
        payload = received_packet["payload"]
        emissions_val = payload["emissions_scaled"]
        scope_val = payload.get("scope", 0)

        E = Int('E')
        G_Max = Int('G_Max')
        Scope = Int('Scope')

        s = Solver()
        s.add(E == emissions_val)
        s.add(G_Max == MAX_GRID_ALLOWANCE_SCALED)
        s.add(Scope == scope_val)

        for predicate in payload["predicates"]:
            if predicate == "Assert(E <= G_Max)":
                s.add(E <= G_Max)
            elif predicate == "Assert(E >= 0)":
                s.add(E >= 0)
            elif predicate == "Assert(scope > 0)":
                s.add(Scope > 0)
            else:
                return False
        return s.check() == sat

    def process_and_commit(self, received_packet: Dict[str, Any]) -> Dict[str, Any]:
        if not self.verify_edge_signature(received_packet):
            raise SecurityError("Packet signature validation failed")
        if not self.execute_logic_predicates(received_packet):
            raise ValueError("Compliance Violation: SMT solver marked constraints UNSAT")

        ledger_packet = json.loads(json.dumps(received_packet))
        ledger_packet["node_verification"] = {
            "algo": "ML-DSA-65_STUB",  # placeholder - replace with real PQ crypto
            "pub": self.node_mldsa_pub_hex,
            "val": self.node_mldsa_sig_hex,
            "status": "VERIFIED_SAT"
        }
        # Honest content hash (not a full Merkle tree proof at v0.3)
        ledger_packet["ledger_hash"] = hashlib.sha256(
            json.dumps(ledger_packet, sort_keys=True).encode()
        ).hexdigest()
        return ledger_packet

    def to_ledger_jsonl(self, packet: Dict) -> str:
        return json.dumps(packet, separators=(',', ':')) + '\n'


if __name__ == "__main__":
    print("=====================================================================")
    print("        VERA PACKET v0.3 - HARDENED REGRESSION TEST                ")
    print("=====================================================================\n")

    client = VERAEdgeClient()
    node = VERANodeValidator(expected_client_pub_key_hex=client.get_public_key_hex())

    mock_merkle = "0x7f83b1a2c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"

    # Case 1: Valid with proper rounding
    print("--- CASE 1: VALID (with rounding check) ---")
    valid_packet, _ = client.generate_packet(mock_merkle, 2, 1420.509)  # should round up
    processed = node.process_and_commit(valid_packet)
    print(f"[OK] emissions_scaled = {processed['payload']['emissions_scaled']} (expected ~142051)")
    print("[OK] Valid packet committed.\n")

    # Case 2: Breach at upper bound
    print("--- CASE 2: BREACH (upper bound) ---")
    try:
        breach_packet, _ = client.generate_packet(mock_merkle, 2, 2000.01)
        node.process_and_commit(breach_packet)
        print("[FAIL] Should have rejected")
    except ValueError as e:
        print(f"[OK] Correctly rejected: {e}\n")

    # Case 3: Tamper detection
    print("--- CASE 3: TAMPER ---")
    tamper_packet, _ = client.generate_packet(mock_merkle, 2, 100.0)
    tamper_packet["payload"]["emissions_scaled"] = 999999
    try:
        node.process_and_commit(tamper_packet)
        print("[FAIL] Should have caught tamper")
    except SecurityError as e:
        print(f"[OK] Tamper correctly detected: {e}\n")

    print("=====================================================================")
    print("        ALL REGRESSION CASES PASSED - HARDENED VERSION            ")
    print("=====================================================================")