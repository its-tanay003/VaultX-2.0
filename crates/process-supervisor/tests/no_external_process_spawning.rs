//! Architecture Test: Ensure NO process spawning occurs outside crates/process-supervisor.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_TOKENS: &[&str] = &[
    "std::process::Command",
    "tokio::process::Command",
    "async_process::Command",
];

/// Recursively scans directory for forbidden process spawning invocations.
pub fn scan_for_violations(dir: &Path, violations: &mut Vec<(PathBuf, &'static str)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name != "target" && name != "node_modules" && name != ".git" {
                    scan_for_violations(&path, violations);
                }
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let path_str = path.to_string_lossy().replace('\\', "/");
                // The ONLY authorized crate in the entire codebase permitted to spawn processes
                if !path_str.contains("crates/process-supervisor") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        for token in FORBIDDEN_TOKENS {
                            if content.contains(token) {
                                violations.push((path.clone(), *token));
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Discovers repository root by walking upward until finding root Cargo.toml.
fn find_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = manifest_dir.clone();
    while let Some(parent) = current.parent() {
        if parent.join("Cargo.toml").exists() && parent.join("crates").exists() {
            return parent.to_path_buf();
        }
        current = parent.to_path_buf();
    }
    manifest_dir.join("../..")
}

#[test]
fn test_no_process_spawning_outside_process_supervisor() {
    let workspace_root = find_workspace_root();
    assert!(
        workspace_root.exists(),
        "Workspace root must exist: {:?}",
        workspace_root
    );

    let mut violations = Vec::new();
    let crates_dir = workspace_root.join("crates");
    if crates_dir.exists() {
        scan_for_violations(&crates_dir, &mut violations);
    }
    let services_dir = workspace_root.join("services");
    if services_dir.exists() {
        scan_for_violations(&services_dir, &mut violations);
    }
    let apps_dir = workspace_root.join("apps");
    if apps_dir.exists() {
        scan_for_violations(&apps_dir, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "Architecture violation! Found forbidden process spawning outside crates/process-supervisor: {:?}",
        violations
    );
}

#[test]
fn test_architecture_test_catches_deliberate_violation() {
    let temp = tempfile::tempdir().expect("Failed to create tempdir");
    let rogue_crate = temp.path().join("crates/rogue-crate/src");
    fs::create_dir_all(&rogue_crate).expect("Failed to create rogue crate dir");

    // Deliberate violation 1: std::process::Command
    let file1 = rogue_crate.join("spawn_std.rs");
    fs::write(
        &file1,
        "pub fn evil() { std::process::Command::new(\"calc.exe\").spawn().ok(); }",
    )
    .expect("Failed to write file1");

    // Deliberate violation 2: tokio::process::Command
    let file2 = rogue_crate.join("spawn_tokio.rs");
    fs::write(
        &file2,
        "pub async fn evil_async() { tokio::process::Command::new(\"cmd.exe\").spawn().ok(); }",
    )
    .expect("Failed to write file2");

    // Deliberate violation 3: async_process::Command
    let file3 = rogue_crate.join("spawn_async.rs");
    fs::write(
        &file3,
        "pub fn evil_async_proc() { async_process::Command::new(\"sh\").spawn().ok(); }",
    )
    .expect("Failed to write file3");

    // Safe file without violations
    let file4 = rogue_crate.join("safe.rs");
    fs::write(&file4, "pub fn safe_calc(a: i32, b: i32) -> i32 { a + b }")
        .expect("Failed to write file4");

    let mut violations = Vec::new();
    scan_for_violations(temp.path(), &mut violations);

    assert_eq!(
        violations.len(),
        3,
        "Architecture scanner should have caught exactly 3 deliberate violations, found: {:?}",
        violations
    );

    let has_std = violations
        .iter()
        .any(|(p, t)| p == &file1 && *t == "std::process::Command");
    let has_tokio = violations
        .iter()
        .any(|(p, t)| p == &file2 && *t == "tokio::process::Command");
    let has_async = violations
        .iter()
        .any(|(p, t)| p == &file3 && *t == "async_process::Command");

    assert!(
        has_std,
        "Architecture scanner must detect std::process::Command violation"
    );
    assert!(
        has_tokio,
        "Architecture scanner must detect tokio::process::Command violation"
    );
    assert!(
        has_async,
        "Architecture scanner must detect async_process::Command violation"
    );
}
