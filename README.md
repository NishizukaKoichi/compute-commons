# Compute Commons

Compute Commons is a permissioned, self-hostable research platform for sharing useful computation while preserving requester data sovereignty, node-operator machine sovereignty, and one-person-one-vote governance.

This repository is the **v0.1 Research MVP**, not the audited v1.0 system. It proves the safe CPU/Wasm control-plane invariants with public or synthetic data. It does **not** protect plaintext from a node operator and must not be used for sensitive data.

## What works today

- immutable, Ed25519-signed workload packages addressed by BLAKE3 digest;
- an approved-only registry and a scheduler that fails closed on unsupported privacy tiers;
- resource-bound, expiring leases, pause/drain/revocation controls, and safe requeue;
- Wasmtime execution with no WASI, filesystem, network, environment, clock, or host imports;
- exact result verification;
- append-only, hash-linked audit and CCU records;
- fixed-cost, non-transferable CCU with idempotent task settlement;
- replay rejection for five-minute signed-envelope windows;
- a deterministic local demo and automated acceptance tests.

## Try it

Install the stable Rust toolchain, then:

```sh
cargo run -p compute-commons -- demo
cargo test --workspace
```

The demo registers a signed Wasm workload, leases it to a local worker, executes it without host capabilities, verifies the result, settles a fixed 10 CCU, and prints the audit evidence as JSON.

Before selecting a privacy tier:

```sh
cargo run -p compute-commons -- explain-privacy P1
```

P0 and P1 explicitly warn that the node operator may read plaintext. P2, P3, and P4 are rejected by the v0.1 scheduler; there is no silent downgrade.

## Scope and roadmap

The authoritative Japanese target specification is preserved at [docs/spec-v1.0-ja.md](docs/spec-v1.0-ja.md). The implemented contract and evidence map are in [docs/V0.1.md](docs/V0.1.md). Security boundaries are in [docs/security/THREAT-MODEL.md](docs/security/THREAT-MODEL.md).

The next milestones require real infrastructure and independent validation: multi-network QUIC/relay and Arcane Commons Mesh integration (v0.2), registry governance and signed updates (v0.3), approved GPU adapters (v0.4), attested CPU/key guardians (v0.5), and an independent security audit and recovery exercise (v1.0).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Please do not report vulnerabilities in public issues.

Licensed under the [MIT License](LICENSE).

