# Kerna-Ledger VCI + VERA Substrata

**Deterministic Verifiable Compute Infrastructure**  
Jacarri Sanders (Jay Sanders) - Even The Odds Foundry  
Chromebook-built. No gatekeepers. SB 253 / Grid compliance focused.

## Core Schema: VERA Packet v0.3 (Integrated + Validated)

VERA Packet v0.3 is the canonical edge-to-node verifiable emissions packet standard.

**Validation Layer Added** (`vera/schema_validation.py`):
- Structural JSON Schema checks
- Expanded Z3 SMT predicate engine (E ≤ G_Max, E ≥ 0, Scope > 0, extensible)
- Full validation pipeline
- Threat model notes (tamper, non-compliance, version drift)
- Extended test harness

This schema + validation is the ingestion contract for Kerna-Ledger (Swarm, GridPulse, Denali).

## Quickstart
```bash
python vera/VERA_Packet_v0.3.py
python vera/schema_validation.py
```

## Status
Production-demo ready. All components verifiable.

Push date: 2026-06-21
GitHub: jabrahns-source/kerna-ledger-vci