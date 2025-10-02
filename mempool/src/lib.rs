use std::collections::BTreeMap;
use serde::{Serialize,Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub from: Vec<u8>,
    pub nonce: u64,
    pub fee: u64,
    pub payload: Vec<u8>,
}

pub struct Mempool {
    // deterministic ordering: (fee desc, nonce asc, txid)
    pub map: BTreeMap<(u64, u64, Vec<u8>), Tx>,
}

impl Mempool {
    pub fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    pub fn add(&mut self, tx: Tx) {
        // reverse fee to get descending
        let key = (u64::MAX - tx.fee, tx.nonce, tx.from.clone());
        self.map.insert(key, tx);
    }

    pub fn pop_for_block(&mut self, max: usize) -> Vec<Tx> {
        let mut res = Vec::new();
        let keys: Vec<_> = self.map.keys().cloned().collect();
        for k in keys.into_iter().take(max) {
            if let Some(tx) = self.map.remove(&k) {
                res.push(tx);
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_order() {
        let mut mp = Mempool::new();
        mp.add(Tx{from: b"a".to_vec(), nonce: 1, fee: 100, payload: vec![]});
        mp.add(Tx{from: b"b".to_vec(), nonce: 1, fee: 200, payload: vec![]});
        let popped = mp.pop_for_block(2);
        assert_eq!(popped[0].from, b"b".to_vec());
        assert_eq!(popped[1].from, b"a".to_vec());
    }
}
