# Compute Commons contributor rules

## Scope

This repository implements the v0.1 public/synthetic-data Research MVP defined in `docs/V0.1.md`. The v1.0 target remains `docs/spec-v1.0-ja.md`.

## Required gate

Run `./scripts/verify.sh` before declaring a change complete. Do not weaken safety or integrity checks to make the gate pass.

## Invariants

- Never silently downgrade a requested privacy tier.
- v0.1 P0/P1 nodes may see plaintext; never imply otherwise or use sensitive data.
- Never execute unapproved or modified packages.
- Wasm receives no ambient host, WASI, filesystem, network, environment, clock, or shell capability.
- CCU is fixed-cost, non-transferable, non-financial, and never voting weight.
- Verification gates settlement; task IDs cannot settle twice.
- Never commit real user data, signing keys, recovery material, credentials, or secrets.

Security, cryptography, identity, dependency, protocol, and architecture changes require a dated ADR with alternatives, risk, and rollback guidance.

