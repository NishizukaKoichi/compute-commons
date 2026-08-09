//! Safety-first domain core for the Compute Commons v0.1 research MVP.
#![allow(clippy::missing_errors_doc)]

mod audit;
mod coordinator;
mod ledger;
mod registry;
mod runtime;

pub use audit::{AuditChain, AuditEvent};
pub use coordinator::{Coordinator, Job, JobState, Lease, Node, PrivacyTier, ResourceLimits};
pub use ledger::{CreditLedger, LedgerEntry, LedgerKind};
pub use registry::{Registry, SignedPackage, WorkloadManifest};
pub use runtime::{ExecutionOutcome, WasmRuntime};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommonsError {
    #[error("workload package is not approved")]
    UnapprovedPackage,
    #[error("workload package digest or signature is invalid")]
    InvalidPackage,
    #[error("requested privacy tier is unavailable; downgrade is forbidden")]
    PrivacyUnavailable,
    #[error("node is paused, drained, revoked, or outside resource limits")]
    NodeUnavailable,
    #[error("request is expired or has already been seen")]
    ReplayRejected,
    #[error("lease is invalid or no longer active")]
    InvalidLease,
    #[error("result did not pass verification")]
    VerificationFailed,
    #[error("credit balance is insufficient")]
    InsufficientCredit,
    #[error("credit transfer is not a supported operation")]
    TransferForbidden,
    #[error("credit amount exceeds the supported integer range")]
    CreditOverflow,
    #[error("unsupported runtime capability or privacy feature")]
    Unsupported,
    #[error("runtime rejected workload: {0}")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, CommonsError>;

#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
