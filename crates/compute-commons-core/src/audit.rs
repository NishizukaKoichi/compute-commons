use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::digest;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub kind: String,
    pub actor: String,
    pub reason_code: String,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Default)]
pub struct AuditChain {
    pub events: Vec<AuditEvent>,
}

impl AuditChain {
    pub fn record(&mut self, kind: &str, actor: &str, reason_code: &str) {
        let previous_hash = self
            .events
            .last()
            .map_or_else(|| "GENESIS".to_owned(), |e| e.hash.clone());
        let sequence = self.events.len() as u64 + 1;
        let canonical = format!("{sequence}|{kind}|{actor}|{reason_code}|{previous_hash}");
        self.events.push(AuditEvent {
            sequence,
            kind: kind.to_owned(),
            actor: actor.to_owned(),
            reason_code: reason_code.to_owned(),
            previous_hash,
            hash: digest(canonical.as_bytes()),
        });
    }

    #[must_use]
    pub fn sign_root(&self, key: &SigningKey) -> Signature {
        key.sign(self.root().as_bytes())
    }

    #[must_use]
    pub fn verify_root(&self, key: &VerifyingKey, signature: &Signature) -> bool {
        key.verify(self.root().as_bytes(), signature).is_ok()
    }

    #[must_use]
    pub fn root(&self) -> String {
        self.events
            .last()
            .map_or_else(|| "GENESIS".to_owned(), |e| e.hash.clone())
    }
}
