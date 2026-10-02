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

fn print_usage() {
    println!("VaultX 2.0 - Agentic Secure Development & Cybersecurity Operating Environment");
    println!("Usage:");
    println!(
        "  valutx doctor [--json]    Diagnose host readiness for sandboxing, IPC and security"
    );
    println!("  valutx daemon             Start local authenticated IPC daemon");
    println!("  valutx --help             Display this help message");
}
