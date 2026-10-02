# VaultX 2.0 CI/CD Infrastructure

This directory contains configuration, scripts, and documentation for the continuous integration and release infrastructure of VaultX 2.0.

- **Primary Workflow**: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- **CI Documentation & Branch Protection**: [`docs/operations/CI.md`](../../docs/operations/CI.md)
- **Threat Model CI Gates**: [`scripts/threat-coverage.ts`](../../scripts/threat-coverage.ts)
- **Schema Compatibility Gates**: [`packages/schemas/scripts/check-breaking.ts`](../../packages/schemas/scripts/check-breaking.ts)
