# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | yes       |
| any tagged release | yes |

## Reporting a Vulnerability

Please report security issues privately to:

**eventheoddsfoundry@gmail.com**

or via GitHub Security Advisories on this repository.

Do not open public issues for vulnerabilities that could affect the integrity of sealed ledgers or cryptographic material.

We aim to acknowledge reports within 48 hours and provide a remediation timeline within 7 days for critical issues affecting the sealing or Merkle pipeline.

## Cryptographic Assumptions

- Ed25519 (RFC 8032) for sealing
- SHA-256 for Merkle leaves and roots
- No reliance on probabilistic or heuristic classifiers in the critical path

Any break of the above primitives or a demonstration that a gate decision can be altered without detection constitutes a critical vulnerability.
