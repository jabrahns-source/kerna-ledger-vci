# Kerna-Ledger VCI + VERA Substrata

[![CI](https://github.com/jabrahns-source/kerna-ledger-vci/actions/workflows/ci.yml/badge.svg)](https://github.com/jabrahns-source/kerna-ledger-vci/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Even The Odds Foundry](https://img.shields.io/badge/Even%20The%20Odds-Foundry-black)](https://github.com/jabrahns-source)

**Deterministic Verifiable Compute Infrastructure for Carbon Compliance (SB 253) and Grid Systems**

Jacarri Sanders / Even The Odds Foundry

## Overview

Production-grade, formally verifiable packet processing for emissions reporting and grid data.

- Strict JCS-style canonicalization (`sort_keys`, compact separators)
- Pre-scaled integer arithmetic (no floating-point in the hash path)
- Real Merkle tree with sibling path proofs
- Schema validation
- Replay protection in the VERA packet pipeline
- Ed25519 edge signing + reserved post-quantum slot (ML-DSA)

## Quick Start

```bash
python3 -m pip install cryptography z3-solver
python3 vera_packet_v0.3.py
python3 -m pytest tests/ -q
```

## Core Modules

| File | Role |
|------|------|
| `vera_packet_v0.3.py` | End-to-end VERA packet pipeline |
| `kerna_ledger_hash.py` | Canonical content hashing (self-ref safe) |
| `merkle.py` | Merkle tree + inclusion proofs |
| `schema_validation.py` | Standalone validator |
| `vera/` | Packet runtime + CAISO backtest helpers |

## Tests

- `tests/test_hash.py` — key-order independence, self-field exclusion, tamper detect
- `tests/test_merkle.py` — empty tree, odd-leaf padding, proof round-trip

## Canonical siblings

- Engine / formal proofs: [Q-Reg](https://github.com/jabrahns-source/Q-Reg)
- Production ledger API: [vera-enterprise-engine](https://github.com/jabrahns-source/vera-enterprise-engine)
- Scope-2 demo: [GridPulse](https://github.com/jabrahns-source/GridPulse)
- Umbrella map: [kerna-ledger](https://github.com/jabrahns-source/kerna-ledger)

## Status

Audit-ready baseline. No silent placeholders. Production-hardened packet + hash + Merkle surface.

Built solo on a Chromebook by Jacarri Sanders.
