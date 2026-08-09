use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{digest, CommonsError, PrivacyTier, ResourceLimits, Result};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadManifest {
    pub name: String,
    pub version: String,
    pub runtime: String,
    pub entrypoint: String,
    pub minimum_privacy: PrivacyTier,
    pub resources: ResourceLimits,
    pub network_deny_all: bool,
    pub deterministic: bool,
    pub verification: String,
    pub reference_cost_ccu: u64,
}

#[derive(Clone, Debug)]
pub struct SignedPackage {
    pub manifest: WorkloadManifest,
    pub module: Vec<u8>,
    pub digest: String,
    pub maintainer: VerifyingKey,
    pub signature: Signature,
}

impl SignedPackage {
    #[must_use]
    pub fn new(manifest: WorkloadManifest, module: Vec<u8>, key: &SigningKey) -> Self {
        let payload = package_payload(&manifest, &module);
        Self {
            manifest,
            module,
            digest: digest(&payload),
            maintainer: key.verifying_key(),
            signature: key.sign(&payload),
        }
    }

    pub fn verify(&self) -> Result<()> {
        let payload = package_payload(&self.manifest, &self.module);
        if self.digest != digest(&payload)
            || self.maintainer.verify(&payload, &self.signature).is_err()
        {
            return Err(CommonsError::InvalidPackage);
        }
        Ok(())
    }
}

fn package_payload(manifest: &WorkloadManifest, module: &[u8]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(manifest).expect("manifest serialization is infallible");
    bytes.extend_from_slice(module);
    bytes
}

#[derive(Default)]
pub struct Registry {
    approved: HashMap<String, SignedPackage>,
}

impl Registry {
    pub fn approve(&mut self, package: SignedPackage) -> Result<String> {
        package.verify()?;
        let digest = package.digest.clone();
        self.approved.insert(digest.clone(), package);
        Ok(digest)
    }

    pub fn get(&self, digest: &str) -> Result<&SignedPackage> {
        let package = self
            .approved
            .get(digest)
            .ok_or(CommonsError::UnapprovedPackage)?;
        package.verify()?;
        Ok(package)
    }
}
