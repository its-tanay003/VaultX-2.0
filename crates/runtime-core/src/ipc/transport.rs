//! Length-delimited binary framing with strict upper size bounds.

use crate::ipc::envelope::{IpcError, IpcErrorCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum permissible frame size over IPC (1 MiB).
pub const MAX_FRAME_SIZE_BYTES: usize = 1_048_576;

/// Reads a single length-delimited frame from the stream.
///
/// Format: [4 bytes Big-Endian length][payload]
/// Immediately rejects any frame announcing a size greater than `MAX_FRAME_SIZE_BYTES`
/// without allocating memory for the body.
pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, IpcError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    if let Err(e) = reader.read_exact(&mut len_buf).await {
        return Err(IpcError::new(
            IpcErrorCode::InvalidRequest,
            format!("Failed to read frame length: {}", e),
        ));
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE_BYTES {
        return Err(IpcError::new(
            IpcErrorCode::ResourceLimit,
            format!(
                "Frame length {} exceeds maximum allowed limit of {} bytes",
                len, MAX_FRAME_SIZE_BYTES
            ),
        ));
    }

    let mut payload = vec![0u8; len];
    if let Err(e) = reader.read_exact(&mut payload).await {
        return Err(IpcError::new(
            IpcErrorCode::InvalidRequest,
            format!("Incomplete frame payload read: {}", e),
        ));
    }

    Ok(payload)
}

/// Writes a single length-delimited frame to the stream.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_SIZE_BYTES {
        return Err(IpcError::new(
            IpcErrorCode::ResourceLimit,
            format!(
                "Outbound payload length {} exceeds maximum allowed limit of {} bytes",
                payload.len(),
                MAX_FRAME_SIZE_BYTES
            ),
        ));
    }

    let len_buf = (payload.len() as u32).to_be_bytes();
    writer
        .write_all(&len_buf)
        .await
        .map_err(|e| IpcError::new(IpcErrorCode::InvalidRequest, e.to_string()))?;

    writer
        .write_all(payload)
        .await
        .map_err(|e| IpcError::new(IpcErrorCode::InvalidRequest, e.to_string()))?;

    writer
        .flush()
        .await
        .map_err(|e| IpcError::new(IpcErrorCode::InvalidRequest, e.to_string()))?;

    Ok(())
}
