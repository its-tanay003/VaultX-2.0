//! Content-addressed storage for large payloads, evidence, and tool outputs.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::compute_payload_hash;

/// Content-addressed storage engine storing blobs keyed by SHA-256 hash.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root_dir: PathBuf,
}

impl ArtifactStore {
    /// Initializes an artifact store at the designated root directory.
    pub fn new(root_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root_dir: root })
    }

    /// Stores raw content bytes into the content-addressed repository.
    ///
    /// Computes the SHA-256 hash `h`, places the payload in `<root>/<h[0..2]>/<h>`,
    /// and returns the hexadecimal hash.
    pub fn put(&self, content: &[u8]) -> std::io::Result<String> {
        let hash = compute_payload_hash(content);
        let prefix = &hash[0..2];
        let sub_dir = self.root_dir.join(prefix);
        fs::create_dir_all(&sub_dir)?;

        let target_file = sub_dir.join(&hash);
        if !target_file.exists() {
            fs::write(&target_file, content)?;
        }

        Ok(hash)
    }

    /// Retrieves content bytes associated with a given SHA-256 hash.
    pub fn get(&self, hash: &str) -> std::io::Result<Option<Vec<u8>>> {
        if hash.len() != 64 {
            return Ok(None);
        }
        let prefix = &hash[0..2];
        let target_file = self.root_dir.join(prefix).join(hash);
        if target_file.is_file() {
            let bytes = fs::read(target_file)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    /// Checks if an artifact with the given hash exists.
    pub fn exists(&self, hash: &str) -> bool {
        if hash.len() != 64 {
            return false;
        }
        let prefix = &hash[0..2];
        self.root_dir.join(prefix).join(hash).is_file()
    }
}
