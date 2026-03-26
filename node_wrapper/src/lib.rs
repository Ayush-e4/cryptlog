#![deny(clippy::all)]

use cryptlog::{Log, Snapshot};
use napi_derive::napi;

#[napi]
pub fn append(path: String, data: String) -> napi::Result<()> {
    let mut log = Log::open(&path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    log.append(data.as_bytes())
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(())
}

#[napi]
pub fn verify(path: String) -> napi::Result<()> {
    let log = Log::open(&path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    log.verify().map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(())
}

#[napi]
pub fn count(path: String) -> napi::Result<u32> {
    let log = Log::open(&path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(log.entry_count() as u32)
}

#[napi]
pub fn snapshot(path: String) -> napi::Result<String> {
    let log = Log::open(&path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(log.snapshot().to_hex())
}

#[napi]
pub fn check_snapshot(path: String, hex: String) -> napi::Result<bool> {
    let log = Log::open(&path).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let snap = Snapshot::from_hex(&hex).ok_or_else(|| napi::Error::from_reason("Invalid snapshot format"))?;
    
    // First verify chain integrity
    log.verify().map_err(|e| napi::Error::from_reason(e.to_string()))?;
    
    // Then verify snapshot match
    Ok(log.verify_snapshot(&snap))
}
