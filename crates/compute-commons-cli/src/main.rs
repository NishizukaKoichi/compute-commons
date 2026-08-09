use anyhow::Result;
use clap::{Parser, Subcommand};
use compute_commons_core::{
    AuditChain, Coordinator, CreditLedger, Job, JobState, Node, PrivacyTier, Registry,
    ResourceLimits, SignedPackage, WasmRuntime, WorkloadManifest,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::json;

#[derive(Parser)]
#[command(
    name = "compute-commons",
    version,
    about = "Compute Commons v0.1 research MVP"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a complete local public-data job and print verifiable evidence.
    Demo,
    /// Print the disclosure shown before submitting a privacy tier.
    ExplainPrivacy { tier: String },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Demo => demo(),
        Command::ExplainPrivacy { tier } => explain_privacy(&tier),
    }
}

fn explain_privacy(value: &str) -> Result<()> {
    let tier = match value.to_ascii_uppercase().as_str() {
        "P0" => PrivacyTier::P0Public,
        "P1" => PrivacyTier::P1MinimizedShard,
        "P2" => PrivacyTier::P2AttestedCpu,
        "P3" => PrivacyTier::P3AttestedAccelerator,
        "P4" => PrivacyTier::P4Cryptographic,
        "LOCAL_ONLY" => PrivacyTier::LocalOnly,
        _ => anyhow::bail!("tier must be P0, P1, P2, P3, P4, or LOCAL_ONLY"),
    };
    println!("{}", tier.disclosure());
    Ok(())
}

fn demo() -> Result<()> {
    let limits = ResourceLimits {
        cpu_threads: 1,
        memory_mib: 64,
        scratch_mib: 16,
        wall_time_seconds: 30,
    };
    let wat = br#"(module (func (export "double") (param i32) (result i32) local.get 0 i32.const 2 i32.mul))"#.to_vec();
    let key = SigningKey::generate(&mut OsRng);
    let package = SignedPackage::new(
        WorkloadManifest {
            name: "public-double".into(),
            version: "1.0.0".into(),
            runtime: "wasm-component".into(),
            entrypoint: "double".into(),
            minimum_privacy: PrivacyTier::P0Public,
            resources: limits,
            network_deny_all: true,
            deterministic: true,
            verification: "EXACT".into(),
            reference_cost_ccu: 10,
        },
        wat,
        &key,
    );
    let mut registry = Registry::default();
    let workload_digest = registry.approve(package)?;
    let mut coordinator = Coordinator::default();
    coordinator.register_node(Node {
        id: "node-local".into(),
        maximum: limits,
        privacy: PrivacyTier::P1MinimizedShard,
        paused: false,
        drained: false,
        revoked: false,
    });
    coordinator.submit(
        Job {
            id: "task-demo".into(),
            owner: "requester".into(),
            workload_digest: workload_digest.clone(),
            privacy: PrivacyTier::P0Public,
            resources: limits,
            max_reserved_ccu: 10,
            expected_output: 42,
            state: JobState::Queued,
        },
        &registry,
    )?;
    let lease = coordinator.lease("task-demo", "node-local", 1_000)?;
    let package = registry.get(&workload_digest)?;
    let outcome =
        WasmRuntime::new()?.execute(&package.module, &package.manifest.entrypoint, 21, 10_000)?;
    coordinator.verify_exact(&lease, outcome.output)?;
    let mut ledger = CreditLedger::default();
    ledger.grant("requester", 3_600)?;
    ledger.settle_verified(
        "task-demo",
        "requester",
        "node-local",
        package.manifest.reference_cost_ccu,
    )?;
    let mut audit = AuditChain::default();
    audit.record("WORKLOAD_APPROVED", "local-community", "MVP_DEMO");
    audit.record("RESULT_APPROVED", "local-verifier", "EXACT_MATCH");
    let signature = audit.sign_root(&key);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "protocol": "compute-commons/1", "scope": "v0.1-research-mvp", "privacy_tier": "P0_PUBLIC",
            "privacy_disclosure": PrivacyTier::P0Public.disclosure(), "workload_digest": workload_digest,
            "lease_id": lease.id, "output": outcome.output, "verification": "EXACT_MATCH",
            "requester_ccu": ledger.balance("requester"), "node_ccu": ledger.balance("node-local"),
            "audit_root": audit.root(), "audit_root_signature_valid": audit.verify_root(&key.verifying_key(), &signature),
            "host_imports_exposed": outcome.module_imports
        }))?
    );
    Ok(())
}
