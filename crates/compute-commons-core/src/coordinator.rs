use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{CommonsError, Registry, Result};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyTier {
    P0Public,
    P1MinimizedShard,
    P2AttestedCpu,
    P3AttestedAccelerator,
    P4Cryptographic,
    LocalOnly,
}

impl PrivacyTier {
    #[must_use]
    pub const fn remote_supported(self) -> bool {
        matches!(self, Self::P0Public | Self::P1MinimizedShard)
    }

    #[must_use]
    pub const fn disclosure(self) -> &'static str {
        match self {
            Self::P0Public => "The node operator may read the plaintext input and model.",
            Self::P1MinimizedShard => "The node operator may read this minimized shard.",
            Self::P2AttestedCpu => "Plaintext requires an attested CPU environment (not in v0.1).",
            Self::P3AttestedAccelerator => {
                "Plaintext requires attested CPU and accelerator environments (not in v0.1)."
            }
            Self::P4Cryptographic => {
                "Only an approved cryptographic plan may operate on ciphertext (not in v0.1)."
            }
            Self::LocalOnly => "The job never leaves the requester's machine.",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_threads: u16,
    pub memory_mib: u32,
    pub scratch_mib: u32,
    pub wall_time_seconds: u32,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub maximum: ResourceLimits,
    pub privacy: PrivacyTier,
    pub paused: bool,
    pub drained: bool,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Leased,
    Verified,
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub owner: String,
    pub workload_digest: String,
    pub privacy: PrivacyTier,
    pub resources: ResourceLimits,
    pub max_reserved_ccu: u64,
    pub expected_output: i32,
    pub state: JobState,
}

#[derive(Clone, Debug)]
pub struct Lease {
    pub id: String,
    pub job_id: String,
    pub node_id: String,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct Coordinator {
    pub jobs: HashMap<String, Job>,
    pub nodes: HashMap<String, Node>,
    leases: HashMap<String, Lease>,
    seen_requests: HashSet<String>,
    sequence: u64,
}

impl Coordinator {
    pub fn register_node(&mut self, node: Node) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn submit(&mut self, mut job: Job, registry: &Registry) -> Result<()> {
        let package = registry.get(&job.workload_digest)?;
        if !job.privacy.remote_supported() || job.privacy < package.manifest.minimum_privacy {
            return Err(CommonsError::PrivacyUnavailable);
        }
        if job.resources != package.manifest.resources
            || job.max_reserved_ccu < package.manifest.reference_cost_ccu
        {
            return Err(CommonsError::NodeUnavailable);
        }
        job.state = JobState::Queued;
        self.jobs.insert(job.id.clone(), job);
        Ok(())
    }

    pub fn lease(&mut self, job_id: &str, node_id: &str, now: u64) -> Result<Lease> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or(CommonsError::InvalidLease)?;
        let node = self
            .nodes
            .get(node_id)
            .ok_or(CommonsError::NodeUnavailable)?;
        if node.paused
            || node.drained
            || node.revoked
            || node.privacy < job.privacy
            || !fits(job.resources, node.maximum)
        {
            return Err(CommonsError::NodeUnavailable);
        }
        self.sequence += 1;
        let lease = Lease {
            id: format!("lease-{}", self.sequence),
            job_id: job_id.to_owned(),
            node_id: node_id.to_owned(),
            expires_at: now + 300,
        };
        job.state = JobState::Leased;
        self.leases.insert(lease.id.clone(), lease.clone());
        Ok(lease)
    }

    pub fn accept_request(
        &mut self,
        request_id: &str,
        issued_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<()> {
        if issued_at > now
            || expires_at < now
            || expires_at.saturating_sub(issued_at) > 300
            || !self.seen_requests.insert(request_id.to_owned())
        {
            return Err(CommonsError::ReplayRejected);
        }
        Ok(())
    }

    pub fn expire_lease(&mut self, lease_id: &str, now: u64) -> Result<()> {
        let lease = self
            .leases
            .remove(lease_id)
            .ok_or(CommonsError::InvalidLease)?;
        if lease.expires_at > now {
            return Err(CommonsError::InvalidLease);
        }
        let job = self
            .jobs
            .get_mut(&lease.job_id)
            .ok_or(CommonsError::InvalidLease)?;
        if job.state != JobState::Verified {
            job.state = JobState::Queued;
        }
        Ok(())
    }

    pub fn verify_exact(&mut self, lease: &Lease, output: i32) -> Result<()> {
        if !self.leases.contains_key(&lease.id) {
            return Err(CommonsError::InvalidLease);
        }
        let job = self
            .jobs
            .get_mut(&lease.job_id)
            .ok_or(CommonsError::InvalidLease)?;
        if output != job.expected_output {
            return Err(CommonsError::VerificationFailed);
        }
        job.state = JobState::Verified;
        Ok(())
    }
}

const fn fits(required: ResourceLimits, maximum: ResourceLimits) -> bool {
    required.cpu_threads <= maximum.cpu_threads
        && required.memory_mib <= maximum.memory_mib
        && required.scratch_mib <= maximum.scratch_mib
        && required.wall_time_seconds <= maximum.wall_time_seconds
}
