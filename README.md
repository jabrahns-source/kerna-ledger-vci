# Kerna-Ledger VCI + VERA Substrata

**Deterministic Verifiable Compute Infrastructure**  
Jacarri Sanders (Jay Sanders) - Even The Odds Foundry  
Chromebook-built. No gatekeepers. SB 253 / Grid compliance focused.

## Core Schema: VERA Packet v0.3 (Now Integrated)

VERA Packet v0.3 is the canonical edge-to-node verifiable emissions packet standard for Kerna-Ledger.

- JCS canonicalization (RFC 8785)
- Ed25519 edge signatures
- Z3 SMT predicate enforcement (E ≤ G_Max, E ≥ 0)
- Fixed-point scaling (no floats)
- Post-quantum ML-DSA node wrapper
- Tamper detection + compliance breach rejection
- Merkle provenance stub
- JSONL ledger append ready

**Demo & Standalone**: `vera_packet_v0.3.py` runs end-to-end with valid/breach/tamper cases.

This schema is the ingestion contract for all downstream Kerna-Ledger components (Swarm gRPC, GridPulse, Denali gate logic).

## Quickstart
```bash
python vera_packet_v0.3.py
```

## Status
Production-demo ready for SPI/PG&E pilots and SB 253 compliance. All artifacts verifiable.

## Components
- VERA Packet v0.3 (edge schema)
- Rust Swarm gRPC runtime (planned ingestion layer)
- Coq formal proofs
- GridPulse PMU telemetry
- PSI-ALPHA quantum fairness
- Sovereign Protocol (DID/VCs)

Push date: 2026-06-21
GitHub: jabrahns-source/kerna-ledger-vci