use compute_commons_core::*;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn limits() -> ResourceLimits {
    ResourceLimits {
        cpu_threads: 1,
        memory_mib: 64,
        scratch_mib: 16,
        wall_time_seconds: 30,
    }
}

fn package() -> SignedPackage {
    SignedPackage::new(WorkloadManifest {
        name: "double".into(), version: "1.0.0".into(), runtime: "wasm-component".into(),
        entrypoint: "double".into(), minimum_privacy: PrivacyTier::P0Public, resources: limits(),
        network_deny_all: true, deterministic: true, verification: "EXACT".into(), reference_cost_ccu: 10,
    }, br#"(module (func (export "double") (param i32) (result i32) local.get 0 i32.const 2 i32.mul))"#.to_vec(), &SigningKey::generate(&mut OsRng))
}

fn setup() -> (Registry, String, Coordinator) {
    let mut registry = Registry::default();
    let digest = registry.approve(package()).unwrap();
    let mut coordinator = Coordinator::default();
    coordinator.register_node(Node {
        id: "node".into(),
        maximum: limits(),
        privacy: PrivacyTier::P1MinimizedShard,
        paused: false,
        drained: false,
        revoked: false,
    });
    (registry, digest, coordinator)
}

fn job(digest: String, privacy: PrivacyTier) -> Job {
    Job {
        id: "task".into(),
        owner: "owner".into(),
        workload_digest: digest,
        privacy,
        resources: limits(),
        max_reserved_ccu: 10,
        expected_output: 42,
        state: JobState::Queued,
    }
}

#[test]
fn unapproved_and_tampered_packages_are_rejected() {
    let registry = Registry::default();
    assert_eq!(
        registry.get("blake3:not-approved").unwrap_err(),
        CommonsError::UnapprovedPackage
    );
    let mut signed = package();
    signed.module.push(0);
    assert_eq!(
        Registry::default().approve(signed).unwrap_err(),
        CommonsError::InvalidPackage
    );
}

#[test]
fn runtime_exposes_no_host_files_or_network_and_limits_fuel() {
    let runtime = WasmRuntime::new().unwrap();
    let valid = package();
    let outcome = runtime
        .execute(&valid.module, "double", 21, 10_000)
        .unwrap();
    assert_eq!(outcome.output, 42);
    assert_eq!(outcome.module_imports, 0);
    let importing = br#"(module (import "wasi_snapshot_preview1" "path_open" (func)) (func (export "run") (param i32) (result i32) local.get 0))"#;
    assert_eq!(
        runtime.execute(importing, "run", 1, 10_000).unwrap_err(),
        CommonsError::Unsupported
    );
}

#[test]
fn privacy_never_downgrades_and_unavailable_tiers_fail_closed() {
    let (registry, digest, mut coordinator) = setup();
    assert_eq!(
        coordinator
            .submit(job(digest, PrivacyTier::P2AttestedCpu), &registry)
            .unwrap_err(),
        CommonsError::PrivacyUnavailable
    );
    assert!(PrivacyTier::P1MinimizedShard
        .disclosure()
        .contains("may read"));
}

#[test]
fn pause_revoke_and_resource_caps_prevent_leases() {
    let (registry, digest, mut coordinator) = setup();
    coordinator
        .submit(job(digest, PrivacyTier::P0Public), &registry)
        .unwrap();
    coordinator.nodes.get_mut("node").unwrap().paused = true;
    assert_eq!(
        coordinator.lease("task", "node", 0).unwrap_err(),
        CommonsError::NodeUnavailable
    );
    coordinator.nodes.get_mut("node").unwrap().paused = false;
    coordinator.nodes.get_mut("node").unwrap().revoked = true;
    assert_eq!(
        coordinator.lease("task", "node", 0).unwrap_err(),
        CommonsError::NodeUnavailable
    );
}

#[test]
fn expired_lease_is_safely_requeued_and_verified_output_survives_pause() {
    let (registry, digest, mut coordinator) = setup();
    coordinator
        .submit(job(digest, PrivacyTier::P0Public), &registry)
        .unwrap();
    let first = coordinator.lease("task", "node", 0).unwrap();
    coordinator.expire_lease(&first.id, 301).unwrap();
    assert_eq!(coordinator.jobs["task"].state, JobState::Queued);
    let second = coordinator.lease("task", "node", 302).unwrap();
    coordinator.verify_exact(&second, 42).unwrap();
    coordinator.nodes.get_mut("node").unwrap().paused = true;
    assert_eq!(coordinator.jobs["task"].state, JobState::Verified);
}

#[test]
fn wrong_result_is_rejected_and_fixed_cost_is_idempotent() {
    let (registry, digest, mut coordinator) = setup();
    coordinator
        .submit(job(digest, PrivacyTier::P0Public), &registry)
        .unwrap();
    let lease = coordinator.lease("task", "node", 0).unwrap();
    assert_eq!(
        coordinator.verify_exact(&lease, 41).unwrap_err(),
        CommonsError::VerificationFailed
    );
    coordinator.verify_exact(&lease, 42).unwrap();
    let mut ledger = CreditLedger::default();
    ledger.grant("owner", 100).unwrap();
    assert!(ledger.settle_verified("task", "owner", "node", 10).unwrap());
    assert!(!ledger.settle_verified("task", "owner", "node", 10).unwrap());
    assert_eq!(ledger.balance("owner"), 90);
    assert_eq!(ledger.balance("node"), 10);
    assert_eq!(
        ledger.transfer("owner", "node", 1).unwrap_err(),
        CommonsError::TransferForbidden
    );
}

#[test]
fn replayed_or_overlong_requests_are_rejected() {
    let mut coordinator = Coordinator::default();
    coordinator.accept_request("r1", 100, 200, 150).unwrap();
    assert_eq!(
        coordinator.accept_request("r1", 100, 200, 150).unwrap_err(),
        CommonsError::ReplayRejected
    );
    assert_eq!(
        coordinator.accept_request("r2", 100, 401, 150).unwrap_err(),
        CommonsError::ReplayRejected
    );
}

#[test]
fn audit_root_is_signed_and_tamper_evident() {
    let key = SigningKey::generate(&mut OsRng);
    let mut audit = AuditChain::default();
    audit.record("LEASE_ISSUED", "coordinator", "MATCHED_POLICY");
    let signature = audit.sign_root(&key);
    assert!(audit.verify_root(&key.verifying_key(), &signature));
    audit.record("RESULT_REJECTED", "verifier", "HASH_MISMATCH");
    assert!(!audit.verify_root(&key.verifying_key(), &signature));
}
