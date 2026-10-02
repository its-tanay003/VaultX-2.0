//! Local Authenticated IPC Subsystem
//!
//! Provides length-delimited framing, peer credential verification,
//! cryptographic session tokens, envelope validation, and idempotency protection.

pub mod envelope;
pub mod idempotency;
pub mod peer;
pub mod server;
pub mod transport;

pub use envelope::{IpcError, IpcErrorCode, IpcMessageEnvelope, IpcResponseEnvelope};
pub use idempotency::IdempotencyStore;
pub use peer::PeerIdentity;
pub use server::{generate_session_token, IpcSecurityContext, IpcServer, CANONICAL_CAPABILITIES};
pub use transport::{read_frame, write_frame, MAX_FRAME_SIZE_BYTES};
