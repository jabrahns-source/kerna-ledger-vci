# Kerna-Ledger VCI

**Cryptographic Ledger and Verifiable Compute Runtime for Deterministic Carbon Compliance & Grid Infrastructure**

**Even The Odds Foundry**  
Jacarri Sanders  
Redding, California  
 eventheoddsfoundry@gmail.com

---

## Overview

Kerna-Ledger VCI is the core verifiable compute infrastructure that replaces probabilistic AI and traditional ledgers with deterministic, cryptographically anchored, formally verifiable execution for high-stakes regulatory and financial environments.

It is the foundational runtime for:

- **Denali Architecture** — deterministic symbolic reasoning and carbon gate logic (see separate whitepaper repo)
- **VERA Substrata** — SB 253 / SB 261 compliant emissions verification and Shared Savings Value (SSV) allocation
- **Sovereign Protocol** — self-sovereign data governance (W3C DID/VCs, granular revocable consent, privacy-preserving revocation)
- **GridPulse Engine** — IEEE C37.118.2 PMU telemetry ingestion and deterministic stability monitoring

The entire stack runs hardware-agnostically on edge devices with minimal dependencies (Python + Z3 + standard library).

## Key Properties

- **Deterministic** — No hallucination, no statistical drift. SMT/Z3 proofs for all compliance and financial invariants.
- **Cryptographically Immutable** — Ed25519 + Merkle anchoring + VERA dual-signature before any evaluation.
- **Commercially Enforced** — 50/50 Shared Savings Value (SSV) runtime invariant that aborts on imbalance.
- **Edge-Ready** — Sub-second evaluation on ARM64, Raspberry Pi, air-gapped containers.
- **Quantum-Extensible** — Native hooks for PSI-ALPHA process matrix fairness primitives.

## Repository Structure (Planned)

```
kerna-ledger-vci/
├── README.md
├── docs/
│   ├── whitepaper/          # Denali + VCI overview PDFs
│   ├── architecture/
├── src/
│   ├── rust/                # Swarm gRPC API (future)
│   ├── python/              # Core engine, VERA, Denali integration
│   ├── coq/                 # Formal proofs (MEV, commitment, SSV invariant)
├── tests/
├── LICENSE
├── CITATION.cff
├── .zenodo.json          # For GitHub-Zenodo integration
```

## Current Status (June 2026)

- Denali Architecture whitepaper v1.0 complete and on Zenodo track: https://github.com/jabrahns-source/denali-whitepaper
- Core symbolic logic mapping, Z3 evaluation loop, and SSV invariant validated on historical CAISO data.
- VERA protocol (Ed25519 + Merkle) implemented and integrated.
- Full source modules being consolidated from development notebooks for open release.

## Whitepapers & DOIs (Pending)

- Denali Architecture: Deterministic Symbolic Reasoning for Regulatory Compliance Infrastructure (v1.0)
- Kerna-Ledger VCI Core Specification (in preparation)
- VERA Substrata SB 253 Platform (in preparation)

## Commercial & Research Use

This infrastructure is designed for immediate pilot deployment with California utilities (PG&E, Sierra Pacific Industries) and SB 253-subject entities. The cryptographically enforced SSV model creates aligned incentives without traditional VC gatekeeping.

Pilot term sheets and integration support: eventheoddsfoundry@gmail.com

## License

© 2026 Even The Odds Foundry. Source available for verified pilots and research collaboration. Commercial licensing preserves the SSV invariant.

*We build the receipts the system can't ignore.*