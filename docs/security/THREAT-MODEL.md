# Threat model: v0.1

## Protected

- The node host is protected from workload filesystem, network, environment, clock, and shell access by exposing no host imports.
- The scheduler rejects unapproved or modified packages and unsupported privacy requirements.
- Replayed request identifiers, invalid results, duplicate settlement, revoked nodes, and excessive declared resources are rejected.

## Not protected

- A P0/P1 node operator can inspect plaintext in process memory.
- This MVP does not provide remote transport, encrypted distributed storage, TEE attestation, guardian key release, traffic-analysis resistance, GPU isolation, or production identity.
- It has not received an independent security audit.

Only public or synthetic data is allowed. Never place secrets in command arguments, environment variables, logs, manifests, fixtures, or coordinator state.

## Trust boundaries

Maintainer signing keys approve immutable packages. The coordinator is trusted for availability and scheduling metadata but must never receive requester decryption keys. Worker operators control whether their machines accept work. Result verification, not worker self-report, gates CCU settlement.

