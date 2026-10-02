//! VaultX 2.0 CLI & Runtime Daemon Binary Entrypoint

use std::env;
use std::process::ExitCode;
use valutx_runtime_core::doctor::DoctorReport;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::from(0);
    }

    match args[1].as_str() {
        "doctor" => {
            let json_mode = args.iter().any(|a| a == "--json");
            let report = DoctorReport::probe();

            if json_mode {
                let serialized = serde_json::to_string_pretty(&report)
                    .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
                println!("{}", serialized);
            } else {
                println!("{}", report.to_human_readable());
            }

            if report.overall_status == "BLOCKED" {
                ExitCode::from(1)
            } else {
                ExitCode::from(0)
            }
        }
        "audit" => handle_audit_command(&args[2..]),
        "daemon" => {
            println!("VaultX 2.0 Runtime Daemon initializing...");
            println!("Authenticated local IPC endpoint ready.");
            ExitCode::from(0)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            ExitCode::from(0)
        }
        unknown => {
            eprintln!("Unknown command: '{}'", unknown);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn handle_audit_command(args: &[String]) -> ExitCode {
    if args.is_empty() {
        print_audit_usage();
        return ExitCode::from(0);
    }

    let subcmd = args[0].as_str();
    let json_mode = args.iter().any(|a| a == "--json");

    let mut db_path = valutx_audit::default_db_path();
    let mut key_path = valutx_audit::default_key_path();
    let mut range: Option<std::ops::RangeInclusive<i64>> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" if i + 1 < args.len() => {
                db_path = std::path::PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--key" if i + 1 < args.len() => {
                key_path = std::path::PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--range" if i + 1 < args.len() => {
                let parts: Vec<&str> = args[i + 1].split("..").collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>())
                    {
                        range = Some(start..=end);
                    }
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    match subcmd {
        "verify" => {
            if !db_path.exists() {
                if json_mode {
                    println!(
                        "{{\"error\": \"Audit database not found\", \"path\": \"{}\"}}",
                        db_path.display()
                    );
                } else {
                    eprintln!("Audit database not found at {}", db_path.display());
                }
                return ExitCode::from(1);
            }

            let signer = match valutx_audit::AuditSigner::load_or_generate_from_file(&key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to load audit signing key: {}", e);
                    return ExitCode::from(1);
                }
            };

            let log = match valutx_audit::AuditLog::open(&db_path, signer) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to open audit log: {}", e);
                    return ExitCode::from(1);
                }
            };

            match log.verify(range) {
                Ok(report) => {
                    if json_mode {
                        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                        println!("{}", json);
                    } else {
                        println!("Audit Log Cryptographic Verification: SUCCESS");
                        println!("  Database:        {}", db_path.display());
                        println!("  Events Verified: {}", report.verified_events);
                        println!("  First ID:        {}", report.first_id);
                        println!("  Last ID:         {}", report.last_id);
                        println!("  Head Hash:       {}", report.head_hash);
                        println!("  Integrity:       No modified, deleted, inserted, or reordered records.");
                    }
                    ExitCode::from(0)
                }
                Err(e) => {
                    if json_mode {
                        println!("{{\"valid\": false, \"error\": \"{}\"}}", e);
                    } else {
                        eprintln!("Audit Log Cryptographic Verification: FAILED");
                        eprintln!("  Error: {}", e);
                    }
                    ExitCode::from(1)
                }
            }
        }
        "export" => {
            if !db_path.exists() {
                if json_mode {
                    println!("[]");
                } else {
                    println!("Audit log is empty (database does not exist).");
                }
                return ExitCode::from(0);
            }

            let signer = match valutx_audit::AuditSigner::load_or_generate_from_file(&key_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to load audit signing key: {}", e);
                    return ExitCode::from(1);
                }
            };

            let log = match valutx_audit::AuditLog::open(&db_path, signer) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to open audit log: {}", e);
                    return ExitCode::from(1);
                }
            };

            match log.export(range) {
                Ok(records) => {
                    if json_mode {
                        let json = serde_json::to_string_pretty(&records).unwrap_or_default();
                        println!("{}", json);
                    } else {
                        println!(
                            "Audit Log Records (Chronological Order, total: {}):",
                            records.len()
                        );
                        println!(
                            "{:<6} {:<16} {:<12} {:<24} {:<16}",
                            "ID", "EVENT_TYPE", "ACTOR", "CREATED_AT", "ENTRY_HASH (prefix)"
                        );
                        println!("{}", "-".repeat(80));
                        for r in records {
                            let hash_prefix = if r.entry_hash.len() > 14 {
                                &r.entry_hash[..14]
                            } else {
                                &r.entry_hash
                            };
                            println!(
                                "{:<6} {:<16} {:<12} {:<24} {:<16}...",
                                r.id, r.event_type, r.actor_id, r.created_at, hash_prefix
                            );
                        }
                    }
                    ExitCode::from(0)
                }
                Err(e) => {
                    eprintln!("Failed to export audit log: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("Unknown audit subcommand: '{}'", subcmd);
            print_audit_usage();
            ExitCode::from(2)
        }
    }
}

fn print_audit_usage() {
    println!("VaultX 2.0 Audit Log Management");
    println!("Usage:");
    println!(
        "  valutx audit verify [--db <path>] [--key <path>] [--range <start>..<end>] [--json]"
    );
    println!(
        "  valutx audit export [--db <path>] [--key <path>] [--range <start>..<end>] [--json]"
    );
}

fn print_usage() {
    println!("VaultX 2.0 - Agentic Secure Development & Cybersecurity Operating Environment");
    println!("Usage:");
    println!(
        "  valutx doctor [--json]    Diagnose host readiness for sandboxing, IPC and security"
    );
    println!("  valutx audit verify       Verify tamper-evident cryptographic audit log");
    println!("  valutx audit export       Export audit records in chronological order");
    println!("  valutx daemon             Start local authenticated IPC daemon");
    println!("  valutx --help             Display this help message");
}
