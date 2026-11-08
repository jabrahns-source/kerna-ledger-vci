# Clean-Room Auditor Verification Guide

**Kerna-Ledger VCI / VERA Substrata**  
Even The Odds Foundry — Jacarri Sanders

This document and the accompanying `auditor_verify.py` script allow any independent party (assurance provider, internal audit, regulator, or third-party reviewer) to verify a sealed VERA packet **without trusting any closed component of the system**.

All verification is performed from the public open-core primitives:
- Canonical JCS-style serialization
- Content hash (self-referential field excluded)
- Ed25519 edge signature
- Integer predicate evaluation
- Merkle inclusion proof

---

## 1. What a VERA Packet Contains (Relevant Fields)

A processed ledger packet contains at minimum:

| Field | Purpose |
|-------|---------|
| `id` / `packet_id` | Unique identifier |
| `ts` / `timestamp` | Issuance time |
| `payload.root` | Merkle root at time of sealing |
| `payload.scope` | Scope number (1 or 2 for current cycle) |
| `payload.emissions_scaled` | Pre-scaled integer emissions value |
| `payload.scale_factor` | Scaling constant (currently 100) |
| `payload.predicates` | List of asserted constraints |
| `sig_edge` | Ed25519 signature block (`algo`, `pub`, `val`) |
| `ledger_hash` | SHA-256 content hash of the packet excluding itself |
| `merkle_proof` | Sibling path for inclusion proof |
| `sequence` | Replay-protection counter |

---

## 2. Verification Steps (Exact Order)

### Step A — Reconstruct Canonical Bytes
Remove the `sig_edge` block.  
Serialize the remaining object with strict JCS rules:
- Keys sorted lexicographically
- No whitespace
- Compact separators
- Proper JSON escaping

### Step B — Verify Edge Signature
Using the public key in `sig_edge.pub` and the signature in `sig_edge.val`, verify that the reconstructed canonical bytes were signed by that key.

### Step C — Re-execute Integer Predicates
Extract `emissions_scaled`.  
For every predicate in `payload.predicates`:
- `Assert(E <= G_Max)` → emissions_scaled ≤ MAX_GRID_ALLOWANCE_SCALED
- `Assert(E >= 0)` → emissions_scaled ≥ 0

Any unknown predicate or failed assertion → reject.

### Step D — Verify Content Hash
Recompute the SHA-256 of the packet after excluding the `ledger_hash` field itself.  
The recomputed value must equal the stored `ledger_hash`.

### Step E — Verify Merkle Inclusion
Using the provided `merkle_proof` (list of `(sibling_hash, direction)` pairs) and the leaf data that was added to the tree, recompute the root and confirm it matches the expected root.

---

## 3. Running the Clean-Room Verifier

```bash
python3 auditor_verify.py --packet path/to/packet.json
```

Exit codes:
- `0` — all checks passed
- `1` — schema / structural failure
- `2` — signature failure
- `3` — predicate / hash / Merkle failure

The script uses only the public modules already present in this repository (`kerna_ledger_hash`, `merkle`, and the cryptography library). No closed code paths are required.

---

## 4. What This Enables for Assurance

An assurance provider can:
1. Receive the sealed packet (and any supporting activity-data or factor manifests).
2. Run the open verifier.
3. Independently re-perform a sample of the underlying calculations.
4. Rely on the cryptographic chain rather than on vendor assertions about calculation integrity.

This is the evidence surface intended for limited-assurance engagements once they become required.

---

## 5. Limitations (Explicit)

- The verifier confirms integrity and deterministic predicate satisfaction of the sealed artifact.
- It does **not** by itself prove that the original activity data or emission factors were correct; that remains the responsibility of the reporting entity’s data-collection processes and the assurance procedures applied to those processes.
- Organizational-boundary decisions and non-reporting attestations are handled by separate sealed packet types (see sibling documentation).

---

Built for independent verification.  
No trust required beyond the open source and the cryptographic primitives.
