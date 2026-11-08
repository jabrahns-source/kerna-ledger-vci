# SB 253 / Initial Regulation Mapping

**Kerna-Ledger VCI + VERA Substrata**  
Even The Odds Foundry — Jacarri Sanders  
Authoritative requirement-to-implementation map

This document maps every material obligation under California SB 253 (Health & Safety Code § 38532) and the CARB Initial Regulation (Title 17 CCR §§ 96070–96077) to the exact modules, packet fields, and verification surfaces in the open core.

It is the single source of truth for how the system addresses both the reporting entity and the future assurance provider.

---

## 1. Applicability & Entity Identification

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Reporting entity definition (U.S.-formed entity, >$1B total annual revenue, does business in California) | HSC § 38532(b); Initial Regulation | Entity metadata captured in packet header / commercial orchestration layer. Open core remains agnostic to the legal determination. |
| Entity-level (not consolidated-family) testing | Initial Regulation | Multi-entity support is handled outside the sealed packet; each sealed artifact is scoped to one reporting entity. |
| Fee calculation & contact information | Initial Regulation (fee schedule) | Outside sealed core. Commercial layer coordinates fee invoice data. |

---

## 2. Organizational Boundary

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Choose one approach and apply consistently: equity share, financial control, or operational control | GHG Protocol Corporate Standard (incorporated by reference) | **Organizational Boundary Packet** (sealed, signed, hashable). Records chosen approach, obligated-entity list, equity percentages where relevant, and explicit exclusions. |
| Document the boundary and any changes | GHG Protocol + future 2027 rulemaking concepts | Boundary decision is itself a first-class sealed artifact. Subsequent restatements generate new sealed packets with clear lineage. |
| List of obligated entities / facilities | CARB draft template expectations | Contained inside the Boundary Packet payload. |

---

## 3. Scope 1 Emissions

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Direct emissions from owned or controlled sources (stationary combustion, mobile combustion, process, fugitive) | GHG Protocol + Initial Regulation | Activity data × emission factor path executed with **pre-scaled integer arithmetic only**. No floating-point in the hash path. |
| Emission factor source + vintage | GHG Protocol documentation requirements | Factor source and vintage bound into the content-hash before sealing. |
| GWP source | GHG Protocol / CARB expectations | GWP version recorded in packet metadata and included in the hash. |

---

## 4. Scope 2 Emissions

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Location-based method | GHG Protocol Scope 2 Guidance | Supported. Grid factors (including CAISO-derived) bound into the sealed packet. |
| Market-based method (where data supports) | GHG Protocol Scope 2 Guidance | Supported in parallel. Both figures can be carried in the same packet with clear provenance. |
| Electricity, steam, heating, cooling | GHG Protocol | Scope field + emissions_scaled + factor provenance. |
| Factor source documentation | Documentation requirements | Bound into content hash. |

GridPulse demonstrates the live Scope 2 receipt + penalty-clock surface that consumes the same packet format.

---

## 5. First-Year (2026) Flexibility

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| May report data already possessed or being collected as of December 5, 2024 | CARB Enforcement Notice + Initial Regulation § 96076(b) | Inventory snapshot can be locked to that historical state. |
| Entities not collecting / not planning to collect as of Dec 5, 2024 may submit letterhead statement of non-reporting | Same | **Non-Reporting Attestation Packet** — sealed, signed artifact that records the non-collection statement for the 2026 cycle only. |
| No limited assurance required for 2026 cycle | CARB guidance | System produces the evidence surface that will be required later; 2026 filings can still be sealed for future defensibility. |

---

## 6. Methodology, Documentation & Audit Trail

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Conformance with GHG Protocol Corporate Standard | HSC § 38532 + Initial Regulation | Calculation kernels and boundary logic designed against the Protocol. |
| Traceability of activity data, factors, GWP, and boundary decisions | Assurance expectations | Every material input and decision is bound into the content hash and Merkle-sealed. |
| Record retention (applicability records, 5 years) | Initial Regulation | Immutable ledger of sealed packets satisfies the retention and demonstrability requirement. |
| Ability for independent party to obtain sufficient appropriate evidence | Future limited / reasonable assurance | Clean-room verifier (`auditor_verify.py`) + open primitives allow an assurance provider to re-verify signature, predicates, content hash, and Merkle inclusion without trusting closed code. |

---

## 7. Submission Path

| Regulatory Requirement | Source | Implementation |
|------------------------|--------|----------------|
| Submit via CARB voluntary intake platform or email to climatedisclosure@arb.ca.gov | CARB 2026 guidance | Export adapters (commercial layer) map sealed packet fields to the draft template / platform fields. The sealed packet itself can accompany the filing as supporting evidence. |
| Acceptable formats for 2026 (existing report, existing program data, or CARB draft template) | CARB guidance | System can produce both a human-readable export and the machine-verifiable sealed artifact. |

---

## 8. Future-Proofing (2027+)

| Upcoming Requirement | Preparation in Current Surface |
|----------------------|--------------------------------|
| Scope 3 (priority categories) | Packet schema is additive; new category modules attach without breaking existing seals. |
| Limited assurance | Clean-room verification surface + sealed decision log already exist. |
| Possible mandatory single organizational-boundary approach | Boundary Packet records the choice explicitly so restatement is clean if CARB later constrains the options. |

---

## 9. Module Reference (Open Core)

| Concern | Primary Module(s) |
|---------|-------------------|
| Canonical serialization + content hash | `kerna_ledger_hash.py` |
| Merkle tree + inclusion proofs | `merkle.py` |
| Packet construction, edge signing, predicate evaluation | `vera_packet_v0.3.py` / `vera/VERA_Packet_v0.3.py` |
| Schema validation | `schema_validation.py` |
| Clean-room independent verification | `auditor_verify.py` + this mapping |
| Formal gate / deadline properties | Q-Reg formal suite (Idris 2) |
| Scope 2 demonstration | GridPulse |

---

## 10. Design Invariant

The open core never asks an auditor to trust a black-box calculation.  
Every number that appears in a sealed packet can be re-derived or re-verified from the public primitives and the inputs that were bound into the hash.

This is the dual-satisfaction surface: the reporting entity obtains a defensible filing artifact; the assurance provider obtains a replayable, cryptographically grounded evidence package.

---

Document status: authoritative for the open core as of the commit that introduced it.  
Any future change to calculation kernels, packet schema, or verification logic must update this mapping in the same commit.
