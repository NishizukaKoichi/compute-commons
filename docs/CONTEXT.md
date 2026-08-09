# Context snapshot

- Date: 2026-08-09
- Scope: public GitHub-ready Compute Commons v0.1 Research MVP
- Canonical repo: `/Volumes/Pensive/Workspace/compute-commons`
- Canonical target: `docs/spec-v1.0-ja.md`

## Goal and success criteria

Deliver an installable, reproducible public/synthetic-data Wasm job path that enforces the first safety invariants and honestly identifies all unavailable v1 guarantees. Format, lint, test, release build, demo, and secret scan must pass.

## Current state

The domain core, CLI demo, acceptance tests, CI, documentation, threat model, and contribution/security policies exist. v0.2 through v1.0 infrastructure and independent review remain outside this implementation claim.

## Decisions

- 2026-08-09: Implement the specification's named v0.1 milestone instead of presenting mocks of unavailable TEE/GPU/network guarantees. See `docs/decisions/0001-v01-scope.md`.
- 2026-08-09: Reject unsupported privacy tiers rather than downgrade them.
- 2026-08-09: Expose no Wasm host imports; network and filesystem remain unavailable by construction.

## Next actions

The next reviewed milestone is v0.2: real iroh QUIC connections across three physical devices, relay fallback, Arcane Commons Mesh storage, encrypted checkpoints, and coordinator recovery.

## Risks

This is not independently audited and cannot protect P0/P1 plaintext from node operators. Mitigation: public/synthetic data only, explicit disclosure, fail-closed scheduling, pinned lockfile, and automated regression gates.

