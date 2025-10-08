use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;
use std::fs::File;
use std::sync::Arc;
use fs2::FileExt;
use std::io::Read;

/// Handle for the database. RocksDB is used under the hood.
#[derive(Clone)]
pub struct DbHandle {
    db: Arc<DB>,
    // optional lockfile to ensure exclusive access across processes
    _lockfile: Arc<File>,
}

/// Convert u64 height to big-endian 8-byte key
fn height_to_key(h: u64) -> [u8; 8] {
    h.to_be_bytes()
}

/// Convert key to u64 height
fn key_to_height(k: &[u8]) -> Option<u64> {
    if k.len() != 8 { return None; }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&k[0..8]);
    Some(u64::from_be_bytes(arr))
}

/// Open (or create) RocksDB at path. Also create and lock a lockfile to avoid multiple
/// processes using the same DB directory.
pub fn open_db<P: AsRef<Path>>(path: P) -> Result<DbHandle, String> {
    let path = path.as_ref();
    std::fs::create_dir_all(path).map_err(|e| format!("create db dir: {}", e))?;
    // lockfile in the dir
    let mut lockpath = path.to_path_buf();
    lockpath.push("db.lock");
    let f = File::create(&lockpath).map_err(|e| format!("create lockfile: {}", e))?;
    // try lock exclusive, fail if already locked
    f.try_lock_exclusive().map_err(|e| format!("failed to lock DB path {}: {}", lockpath.display(), e))?;

    let mut opts = Options::default();
    opts.create_if_missing(true);
    // tuning for production: increase write buffer, etc. (tunable)
    opts.set_max_open_files(1024);
    opts.optimize_for_point_lookup(64);

    let db = DB::open(&opts, path).map_err(|e| format!("rocksdb open: {}", e))?;
    Ok(DbHandle { db: Arc::new(db), _lockfile: Arc::new(f) })
}

/// Save block bytes under the numeric height key
pub fn save_block(handle: &DbHandle, height: u64, data: &[u8]) -> Result<(), String> {
    let key = height_to_key(height);
    handle.db.put(key, data).map_err(|e| format!("rocksdb put: {}", e))
}

/// Get block bytes by height
pub fn get_block(handle: &DbHandle, height: u64) -> Result<Option<Vec<u8>>, String> {
    let key = height_to_key(height);
    handle.db.get(key).map_err(|e| format!("rocksdb get: {}", e))
}

/// List all heights in DB (sorted ascending)
pub fn list_heights(handle: &DbHandle) -> Result<Vec<u64>, String> {
    let mut res = Vec::new();
    let iter = handle.db.iterator(rocksdb::IteratorMode::Start);
    for item in iter {
        let (k, _) = item.map_err(|e| format!("rocksdb iter: {}", e))?;
        if let Some(h) = key_to_height(&k) {
            res.push(h);
        }
    }
    res.sort_unstable();
    Ok(res)
}

/// Remove a block by height
pub fn remove_block(handle: &DbHandle, height: u64) -> Result<(), String> {
    let key = height_to_key(height);
    handle.db.delete(key).map_err(|e| format!("rocksdb delete: {}", e))
}

/// Compact DB (full range)
pub fn compact_db(handle: &DbHandle) -> Result<(), String> {
    handle.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    Ok(())
}
