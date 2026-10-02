//! In-memory bounded idempotency store for mutating IPC operations.

use crate::ipc::envelope::{IpcError, IpcErrorCode};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct IdempotencyRecord {
    payload_hash: u64,
    cached_response: Option<Value>,
}

/// Thread-safe in-memory store tracking mutating idempotency keys.
#[derive(Debug, Default, Clone)]
pub struct IdempotencyStore {
    records: HashMap<String, IdempotencyRecord>,
}

impl IdempotencyStore {
    /// Creates a fresh idempotency store.
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Computes a lightweight structural hash of a JSON value.
    fn compute_hash(val: &Value) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        // Canonical string representation for stable hashing
        val.to_string().hash(&mut hasher);
        hasher.finish()
    }

    /// Checks an incoming idempotency key against prior records.
    ///
    /// - If the key is new: records it as in-flight and returns `Ok(None)`.
    /// - If the key was previously executed with the identical payload: returns `Ok(cached_response)`.
    /// - If the key is replayed with a different payload: returns `Err(IpcErrorCode::IdempotencyConflict)`.
    pub fn check_or_record(
        &mut self,
        key: &str,
        payload: &Value,
    ) -> Result<Option<Value>, IpcError> {
        let current_hash = Self::compute_hash(payload);

        if let Some(existing) = self.records.get(key) {
            if existing.payload_hash != current_hash {
                return Err(IpcError::new(
                    IpcErrorCode::IdempotencyConflict,
                    format!(
                        "Idempotency key '{}' was previously used with a different request payload",
                        key
                    ),
                ));
            }
            return Ok(existing.cached_response.clone());
        }

        // Register initial in-flight key
        self.records.insert(
            key.to_string(),
            IdempotencyRecord {
                payload_hash: current_hash,
                cached_response: None,
            },
        );

        Ok(None)
    }

    /// Stores the completed result for an idempotency key.
    pub fn save_response(&mut self, key: &str, response: Value) {
        if let Some(record) = self.records.get_mut(key) {
            record.cached_response = Some(response);
        }
    }
}
