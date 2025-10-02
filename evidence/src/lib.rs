use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use anyhow::Result;
use std::collections::BTreeMap;

/// A simple signed message record used by the evidence manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedMessage {
    pub message_type: String,
    pub signer: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Evidence about misbehavior (e.g., equivocation)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub offender: Vec<u8>,
    pub first: SignedMessage,
    pub second: SignedMessage,
    pub evidence_hash: [u8; 32],
}

impl Evidence {
    /// Produce a deterministic evidence id (hash)
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.offender);
        h.update(&self.first.signature);
        h.update(&self.second.signature);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d[..32]);
        out
    }
}

/// Simple EvidenceManager: stores first-seen signed messages per (signer, message_type)
/// and produces evidence if a new conflicting message is seen.
pub struct EvidenceManager {
    seen: BTreeMap<(String, String), SignedMessage>,
    pub evidences: BTreeMap<String, Evidence>,
}

impl EvidenceManager {
    pub fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
            evidences: BTreeMap::new(),
        }
    }

    pub fn feed(&mut self, msg: SignedMessage) -> Result<Option<Evidence>> {
        let signer_hex = hex::encode(&msg.signer);
        let key = (signer_hex.clone(), msg.message_type.clone());
        if let Some(prev) = self.seen.get(&key) {
            if prev.signature != msg.signature && prev.payload != msg.payload {
                let ev = Evidence {
                    offender: msg.signer.clone(),
                    first: prev.clone(),
                    second: msg.clone(),
                    evidence_hash: {
                        let mut h = Sha256::new();
                        h.update(&signer_hex.as_bytes());
                        h.update(&prev.signature);
                        h.update(&msg.signature);
                        let d = h.finalize();
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&d[..32]);
                        out
                    },
                };
                let id = hex::encode(ev.evidence_hash);
                self.evidences.insert(id.clone(), ev.clone());
                return Ok(Some(ev));
            } else {
                return Ok(None);
            }
        } else {
            self.seen.insert(key, msg);
            return Ok(None);
        }
    }

    pub fn has_evidence_for(&self, signer: &[u8]) -> bool {
        let signer_hex = hex::encode(signer);
        self.evidences.values().any(|e| hex::encode(&e.offender) == signer_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signed(msg_type: &str, signer: &[u8], payload: &[u8], sig_byte: u8) -> SignedMessage {
        SignedMessage {
            message_type: msg_type.to_string(),
            signer: signer.to_vec(),
            payload: payload.to_vec(),
            signature: vec![sig_byte; 64],
        }
    }

    #[test]
    fn detect_equivocation() {
        let mut mgr = EvidenceManager::new();
        let s1 = sample_signed("vote", b"node1", b"payload-A", 1);
        let s2 = sample_signed("vote", b"node1", b"payload-B", 2);

        assert!(mgr.feed(s1.clone()).unwrap().is_none());
        let maybe = mgr.feed(s2.clone()).unwrap();
        assert!(maybe.is_some());
        let ev = maybe.unwrap();
        assert_eq!(hex::encode(ev.offender), hex::encode(b"node1"));
        assert!(mgr.has_evidence_for(b"node1"));
    }

    #[test]
    fn ignore_identical_messages() {
        let mut mgr = EvidenceManager::new();
        let s1 = sample_signed("vote", b"nodeX", b"payload", 5);
        let s1_dup = sample_signed("vote", b"nodeX", b"payload", 5);
        assert!(mgr.feed(s1.clone()).unwrap().is_none());
        assert!(mgr.feed(s1_dup).unwrap().is_none()); // identical — no evidence
    }
}
