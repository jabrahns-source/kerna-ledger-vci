# VERA Packet v0.3 — Schema & Runtime

Core deterministic verifiable emissions packet for Kerna-Ledger VCI.

## Files

- `VERA_Packet_v0.3.py` — Primary packet construction, sealing, and validation logic.
- `live_caiso_backtest.py` — Empirical CAISO-oriented backtest harness.
- `schema_validation.py` — Schema-level checks for packet integrity.

## Quickstart

```bash
python vera/VERA_Packet_v0.3.py --demo
# or from repo root
python vera_packet_v0.3.py --demo
```

## Integration

This layer feeds the Q-Reg deterministic gate engine and the vera-enterprise-engine receipt ledger.
All operations are designed to be fully deterministic, cryptographically sealed (Ed25519 where applicable), and Merkle-chained for provenance.

See root README and `Kerna-Ledger_VCI_Whitepaper_v1.md` for the broader architecture.

Even The Odds Foundry — zero stochastic drift.
