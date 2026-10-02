//! Append-only SQLite WAL storage engine for audit events.

use chrono::Utc;
use rusqlite::{params, Connection};
use std::fs;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::crypto::{compute_entry_hash, AuditSigner};
use crate::error::{AuditError, VerificationError};
use crate::models::{AuditEventRecord, VerificationReport, GENESIS_HASH};

/// SQLite-backed append-only audit log.
#[derive(Clone)]
pub struct AuditLog {
    conn: Arc<Mutex<Connection>>,
    signer: Arc<AuditSigner>,
}

impl AuditLog {
    /// Opens or creates an append-only audit database at the specified path.
    ///
    /// Configures SQLite with Write-Ahead Logging (WAL) and synchronous normal mode.
    pub fn open(db_path: impl AsRef<Path>, signer: AuditSigner) -> Result<Self, AuditError> {
        let path = db_path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;

        // Configure WAL mode and pragmas for robustness and high throughput
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS audit_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 run_id TEXT,
                 event_type TEXT NOT NULL,
                 actor_id TEXT NOT NULL,
                 payload_hash TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 prev_hash TEXT NOT NULL,
                 entry_hash TEXT NOT NULL,
                 signature TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_audit_events_run_id ON audit_events(run_id);
             CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            signer: Arc::new(signer),
        })
    }

    /// Opens the default runtime audit log using the system-private directory.
    ///
    /// Loads or generates the dedicated Ed25519 signing key outside any sandbox mount.
    pub fn open_default() -> Result<Self, AuditError> {
        let db_path = crate::default_db_path();
        let key_path = crate::default_key_path();
        let signer = AuditSigner::load_or_generate_from_file(&key_path)?;
        Self::open(&db_path, signer)
    }

    /// Exposes raw connection for test tampering assertions.
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Exposes reference to current signer.
    pub fn signer(&self) -> Arc<AuditSigner> {
        Arc::clone(&self.signer)
    }

    /// Returns total count of audit events in the database.
    pub fn count(&self) -> Result<i64, AuditError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM audit_events")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    /// Appends a new event to the hash chain inside an exclusive transaction.
    ///
    /// Enforces:
    /// 1. Retrieval of the current head record's entry_hash.
    /// 2. Deterministic sequential ID assignment (`head.id + 1` or `1`).
    /// 3. SHA-256 entry hash computation over canonical record components.
    /// 4. Ed25519 digital signature of entry hash.
    /// 5. Atomic insertion into the WAL database.
    pub fn append(
        &self,
        run_id: Option<&str>,
        event_type: &str,
        actor_id: &str,
        payload_hash: &str,
    ) -> Result<AuditEventRecord, AuditError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        // Fetch current chain head
        let head: Option<(i64, String)> = {
            let mut stmt =
                tx.prepare("SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1")?;
            stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
                .ok()
        };

        let (next_id, prev_hash) = match head {
            Some((last_id, last_hash)) => (last_id + 1, last_hash),
            None => (1, GENESIS_HASH.to_string()),
        };

        let created_at = Utc::now().to_rfc3339();
        let entry_hash = compute_entry_hash(
            next_id,
            run_id,
            event_type,
            actor_id,
            payload_hash,
            &created_at,
            &prev_hash,
        );

        let signature = self.signer.sign_entry_hash(&entry_hash);

        tx.execute(
            "INSERT INTO audit_events (id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                next_id,
                run_id,
                event_type,
                actor_id,
                payload_hash,
                created_at,
                prev_hash,
                entry_hash,
                signature,
            ],
        )?;

        tx.commit()?;

        Ok(AuditEventRecord {
            id: next_id,
            run_id: run_id.map(str::to_string),
            event_type: event_type.to_string(),
            actor_id: actor_id.to_string(),
            payload_hash: payload_hash.to_string(),
            created_at,
            prev_hash,
            entry_hash,
            signature,
        })
    }

    /// Appends a batch of audit events atomically inside a single transaction.
    ///
    /// Preserves strict cryptographic hash-chaining across all events in the batch.
    pub fn append_batch(
        &self,
        events: &[(Option<&str>, &str, &str, &str)],
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let mut head: Option<(i64, String)> = {
            let mut stmt =
                tx.prepare("SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1")?;
            stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
                .ok()
        };

        let mut records = Vec::with_capacity(events.len());

        for &(run_id, event_type, actor_id, payload_hash) in events {
            let (next_id, prev_hash) = match head {
                Some((last_id, ref last_hash)) => (last_id + 1, last_hash.clone()),
                None => (1, GENESIS_HASH.to_string()),
            };

            let created_at = Utc::now().to_rfc3339();
            let entry_hash = compute_entry_hash(
                next_id,
                run_id,
                event_type,
                actor_id,
                payload_hash,
                &created_at,
                &prev_hash,
            );

            let signature = self.signer.sign_entry_hash(&entry_hash);

            tx.execute(
                "INSERT INTO audit_events (id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    next_id,
                    run_id,
                    event_type,
                    actor_id,
                    payload_hash,
                    created_at,
                    prev_hash,
                    entry_hash,
                    signature,
                ],
            )?;

            head = Some((next_id, entry_hash.clone()));

            records.push(AuditEventRecord {
                id: next_id,
                run_id: run_id.map(str::to_string),
                event_type: event_type.to_string(),
                actor_id: actor_id.to_string(),
                payload_hash: payload_hash.to_string(),
                created_at,
                prev_hash,
                entry_hash,
                signature,
            });
        }

        tx.commit()?;
        Ok(records)
    }

    /// Verifies the cryptographic and sequential integrity of the audit chain over an optional ID range.
    ///
    /// Detects:
    /// - Gaps in sequential ID progression (deleted rows).
    /// - Out-of-order or reordered records.
    /// - Injected / inserted records with invalid hashes or signatures.
    /// - Tampered metadata or payload hashes (`HashMismatch`).
    /// - Invalid or forged Ed25519 signatures (`SignatureInvalid`).
    pub fn verify(
        &self,
        range: Option<RangeInclusive<i64>>,
    ) -> Result<VerificationReport, AuditError> {
        let conn = self.conn.lock().unwrap();

        let query = match &range {
            Some(r) => format!(
                "SELECT id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature
                 FROM audit_events WHERE id >= {} AND id <= {} ORDER BY id ASC",
                r.start(),
                r.end()
            ),
            None => "SELECT id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature
                     FROM audit_events ORDER BY id ASC"
                .to_string(),
        };

        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;

        let mut expected_id: Option<i64> = None;
        let mut expected_prev_hash: Option<String> = None;
        let mut first_id: Option<i64> = None;
        let mut last_id = 0i64;
        let mut head_hash = String::new();
        let mut count = 0usize;

        while let Some(row) = rows.next()? {
            let record = AuditEventRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                event_type: row.get(2)?,
                actor_id: row.get(3)?,
                payload_hash: row.get(4)?,
                created_at: row.get(5)?,
                prev_hash: row.get(6)?,
                entry_hash: row.get(7)?,
                signature: row.get(8)?,
            };

            if first_id.is_none() {
                first_id = Some(record.id);
            }
            last_id = record.id;
            count += 1;

            // 1. Verify sequence monotonicity
            if let Some(exp_id) = expected_id {
                if record.id != exp_id {
                    return Err(VerificationError::BrokenSequence {
                        id: record.id,
                        expected: exp_id,
                        actual: record.id,
                    }
                    .into());
                }
            } else if range.is_none() && record.id != 1 {
                return Err(VerificationError::BrokenSequence {
                    id: record.id,
                    expected: 1,
                    actual: record.id,
                }
                .into());
            }

            // 2. Verify previous hash linkage
            if let Some(exp_hash) = expected_prev_hash {
                if record.prev_hash != exp_hash {
                    return Err(VerificationError::PrevHashMismatch {
                        id: record.id,
                        expected: exp_hash,
                        actual: record.prev_hash,
                    }
                    .into());
                }
            } else if range.is_none() && record.prev_hash != GENESIS_HASH {
                return Err(VerificationError::PrevHashMismatch {
                    id: record.id,
                    expected: GENESIS_HASH.to_string(),
                    actual: record.prev_hash,
                }
                .into());
            }

            // 3. Recompute and verify entry_hash
            let computed_hash = compute_entry_hash(
                record.id,
                record.run_id.as_deref(),
                &record.event_type,
                &record.actor_id,
                &record.payload_hash,
                &record.created_at,
                &record.prev_hash,
            );

            if computed_hash != record.entry_hash {
                return Err(VerificationError::HashMismatch {
                    id: record.id,
                    expected: computed_hash,
                    actual: record.entry_hash,
                }
                .into());
            }

            // 4. Verify Ed25519 signature
            if let Err(e) = self
                .signer
                .verify_entry_signature(&record.entry_hash, &record.signature)
            {
                return Err(VerificationError::SignatureInvalid {
                    id: record.id,
                    reason: e.to_string(),
                }
                .into());
            }

            expected_id = Some(record.id + 1);
            expected_prev_hash = Some(record.entry_hash.clone());
            head_hash = record.entry_hash;
        }

        if count == 0 {
            return Err(VerificationError::EmptyLog.into());
        }

        Ok(VerificationReport {
            valid: true,
            verified_events: count,
            first_id: first_id.unwrap_or(0),
            last_id,
            head_hash,
        })
    }

    /// Exports audit events in strict chronological order.
    pub fn export(
        &self,
        range: Option<RangeInclusive<i64>>,
    ) -> Result<Vec<AuditEventRecord>, AuditError> {
        let conn = self.conn.lock().unwrap();

        let query = match &range {
            Some(r) => format!(
                "SELECT id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature
                 FROM audit_events WHERE id >= {} AND id <= {} ORDER BY id ASC",
                r.start(),
                r.end()
            ),
            None => "SELECT id, run_id, event_type, actor_id, payload_hash, created_at, prev_hash, entry_hash, signature
                     FROM audit_events ORDER BY id ASC"
                .to_string(),
        };

        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok(AuditEventRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                event_type: row.get(2)?,
                actor_id: row.get(3)?,
                payload_hash: row.get(4)?,
                created_at: row.get(5)?,
                prev_hash: row.get(6)?,
                entry_hash: row.get(7)?,
                signature: row.get(8)?,
            })
        })?;

        let mut records = Vec::new();
        for r in rows {
            records.push(r?);
        }

        Ok(records)
    }
}
