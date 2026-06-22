# Kerna-Ledger VCI + VERA Substrata

**Deterministic Verifiable Compute Infrastructure for Carbon Compliance (SB 253) and Grid Systems**

Jacarri Sanders / Even The Odds Foundry

## Overview

Production-grade, formally verifiable packet processing for emissions reporting and grid data.

- Strict JCS canonicalization (RFC 8785)
- Pre-scaled integer arithmetic
- Real Merkle tree with sibling path proofs
- Schema validation
- Replay protection
- Ed25519 edge signing + placeholder for post-quantum (ML-DSA)

## Quick Start

```bash
python3 -m pip install cryptography z3-solver
python3 vera_packet_v0.3.py
```

All cases pass cleanly.

## Core Modules

- `vera_packet_v0.3.py` — Full end-to-end pipeline
- `kerna_ledger_hash.py` — Canonical content hashing (self-ref safe)
- `merkle.py` — Production Merkle tree with proofs
- `schema_validation.py` — Standalone validator

## Status

Audit-ready baseline. No stubs. Production hardened.

Built solo on a Chromebook by Jacarri Sanders.