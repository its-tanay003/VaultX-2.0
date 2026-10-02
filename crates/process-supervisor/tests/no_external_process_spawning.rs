//! Architecture Test: Ensure NO process spawning occurs outside crates/process-supervisor.

use std::fs;
use std::path::{Path, PathBuf};

fn check_dir(dir: &Path, violations: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name != "target" && name != "node_modules" && name != ".git" {
                    check_dir(&path, violations);
                }
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                // Ignore process-supervisor crate itself
                let path_str = path.to_string_lossy().replace('\\', "/");
                if !path_str.contains("crates/process-supervisor") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if content.contains("std::process::Command") {
                            violations.push(path.clone());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_no_process_spawning_outside_process_supervisor() {
    let root = Path::new("../../crates");
    let mut violations = Vec::new();
    if root.exists() {
        check_dir(root, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "Architecture violation! Found forbidden std::process::Command outside process-supervisor: {:?}",
        violations
    );
}
