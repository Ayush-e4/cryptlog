use chrono::{Local, TimeZone};
use colored::Colorize;
use cryptlog::{CryptLogError, Log, Snapshot};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    let log_path = env::var("CRYPTLOG_PATH").unwrap_or_else(|_| "audit.clog".to_string());

    match args[1].as_str() {
        "append" => {
            if args.len() < 3 {
                eprintln!("{} usage: cryptlog append <message>", "error:".red().bold());
                std::process::exit(1);
            }
            let message = args[2..].join(" ");
            let mut log = Log::open(&log_path).expect("failed to open log");
            log.append(&message).expect("failed to append");

            println!(
                "{} entry #{} appended to {}",
                "✓".green().bold(),
                log.entry_count().to_string().cyan(),
                log_path.dimmed()
            );
            println!(
                "  {} {}",
                "hash:".dimmed(),
                &hex(log.last_hash())[..16].dimmed()
            );
        }

        "verify" => {
            let log = Log::open(&log_path).expect("failed to open log");
            let count = log.entry_count();

            print!("verifying {} entries... ", count.to_string().cyan());

            match log.verify() {
                Ok(_) => {
                    println!("{}", "chain intact".green().bold());
                    println!("  {} {} entries", "✓".green(), count.to_string().cyan());
                    println!(
                        "  {} {}",
                        "last hash:".dimmed(),
                        hex(log.last_hash()).dimmed()
                    );
                }
                Err(CryptLogError::ChainBroken { at_entry }) => {
                    println!("{}", "TAMPERED".red().bold());
                    println!();
                    eprintln!(
                        "  {} chain broken at entry {}",
                        "✗".red().bold(),
                        at_entry.to_string().red().bold()
                    );
                    eprintln!(
                        "  {} entries 0..{} are valid, entry {} and beyond are suspect",
                        "!".yellow(),
                        at_entry.saturating_sub(1),
                        at_entry
                    );
                    std::process::exit(2);
                }
                Err(e) => {
                    eprintln!("{} {:?}", "error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        "tail" => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);

            let log = Log::open(&log_path).expect("failed to open log");
            let entries = log.read_all().expect("failed to read log");

            if entries.is_empty() {
                println!("{}", "log is empty".dimmed());
                return;
            }

            let start = entries.len().saturating_sub(n);
            let showing = entries.len() - start;

            println!(
                "{} {} (showing last {})\n",
                "cryptlog".cyan().bold(),
                log_path.dimmed(),
                showing.to_string().cyan()
            );

            // header
            println!(
                "  {:<6} {:<28} {:<45} {}",
                "#".dimmed(),
                "timestamp".dimmed(),
                "message".dimmed(),
                "hash".dimmed()
            );
            println!("  {}", "─".repeat(90).dimmed());

            for (i, entry) in entries[start..].iter().enumerate() {
                let idx = start + i;
                let ts = format_ts(entry.timestamp);
                let data = String::from_utf8_lossy(&entry.data);
                let short_hash = &hex(&entry.hash)[..12];

                // truncate long messages cleanly
                let msg = if data.len() > 42 {
                    format!("{}…", &data[..41])
                } else {
                    data.to_string()
                };

                println!(
                    "  {:<6} {:<28} {:<45} {}",
                    idx.to_string().dimmed(),
                    ts.dimmed(),
                    msg,
                    short_hash.cyan()
                );
            }

            println!(
                "\n  {} {}",
                "total:".dimmed(),
                entries.len().to_string().cyan()
            );
        }

        "range" => {
            if args.len() < 4 {
                eprintln!(
                    "{} usage: cryptlog range <from_unix_ms> <to_unix_ms>",
                    "error:".red().bold()
                );
                std::process::exit(1);
            }
            let from: u64 = args[2].parse().expect("invalid from timestamp");
            let to: u64 = args[3].parse().expect("invalid to timestamp");

            let log = Log::open(&log_path).expect("failed to open log");
            let entries = log
                .read_range(from * 1000, to * 1000)
                .expect("failed to read");

            if entries.is_empty() {
                println!("{}", "no entries in that range".dimmed());
                return;
            }

            println!("{} entries in range\n", entries.len().to_string().cyan());

            for (i, entry) in entries.iter().enumerate() {
                println!(
                    "  {} {} | {}",
                    i.to_string().dimmed(),
                    format_ts(entry.timestamp).dimmed(),
                    String::from_utf8_lossy(&entry.data)
                );
            }
        }

        "snapshot" => {
            let log = Log::open(&log_path).expect("failed to open log");
            let snap = log.snapshot();
            println!("{}", snap.to_hex());
            eprintln!(
                "\n  {} save this value somewhere the attacker can't touch.",
                "tip:".cyan().bold()
            );
            eprintln!(
                "  {} to verify later: {}",
                "→".dimmed(),
                "cryptlog check-snapshot <snapshot>".green()
            );
        }

        "check-snapshot" => {
            if args.len() < 3 {
                eprintln!(
                    "{} usage: cryptlog check-snapshot <snapshot_hex>",
                    "error:".red().bold()
                );
                std::process::exit(1);
            }

            let snap = Snapshot::from_hex(&args[2]).unwrap_or_else(|| {
                eprintln!("{} invalid snapshot format", "error:".red().bold());
                eprintln!(
                    "  expected format: {}",
                    "<count>:<64-char-hex-hash>".dimmed()
                );
                std::process::exit(1);
            });

            let log = Log::open(&log_path).expect("failed to open log");

            // First verify chain integrity
            if let Err(e) = log.verify() {
                eprintln!("{} chain verification failed: {}", "✗".red().bold(), e);
                std::process::exit(2);
            }

            // Then verify against snapshot
            if log.verify_snapshot(&snap) {
                println!(
                    "{} log matches snapshot — {} entries, chain intact",
                    "✓".green().bold(),
                    log.entry_count().to_string().cyan()
                );
            } else {
                eprintln!(
                    "{} log does NOT match snapshot — possible full rewrite attack",
                    "✗".red().bold()
                );
                eprintln!(
                    "  {} snapshot: {} entries, hash {}…",
                    "expected:".dimmed(),
                    snap.entry_count,
                    &snap.to_hex().split(':').next_back().unwrap_or("")[..12]
                );
                eprintln!(
                    "  {} current:  {} entries, hash {}…",
                    "got:".dimmed(),
                    log.entry_count(),
                    &hex(log.last_hash())[..12]
                );
                std::process::exit(2);
            }
        }

        "count" => {
            let log = Log::open(&log_path).expect("failed to open log");
            println!(
                "{} entries in {}",
                log.entry_count().to_string().cyan().bold(),
                log_path.dimmed()
            );
        }

        "help" | "--help" | "-h" => print_usage(),

        _ => {
            eprintln!("{} unknown command '{}'\n", "error:".red().bold(), args[1]);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("{}", "cryptlog".cyan().bold());
    println!(
        "{}",
        "tamper-evident append-only log using SHA-256 hash chains".dimmed()
    );
    println!();
    println!("{}", "usage:".bold());
    println!(
        "  {} {:<30} append a new entry to the log",
        "cryptlog".cyan(),
        "append <msg>".green()
    );
    println!(
        "  {} {:<30} verify the entire chain — exits 2 if tampered",
        "cryptlog".cyan(),
        "verify".green()
    );
    println!(
        "  {} {:<30} show last n entries (default 10)",
        "cryptlog".cyan(),
        "tail [n]".green()
    );
    println!(
        "  {} {:<30} show entries between two unix timestamps (ms)",
        "cryptlog".cyan(),
        "range <from_ms> <to_ms>".green()
    );
    println!(
        "  {} {:<30} export hash anchor for external storage",
        "cryptlog".cyan(),
        "snapshot".green()
    );
    println!(
        "  {} {:<30} verify log against a saved snapshot",
        "cryptlog".cyan(),
        "check-snapshot <snap>".green()
    );
    println!(
        "  {} {:<30} print total entry count",
        "cryptlog".cyan(),
        "count".green()
    );
    println!();
    println!("{}", "env:".bold());
    println!(
        "  {}   log file path (default: audit.clog)",
        "CRYPTLOG_PATH".green()
    );
    println!();
    println!("{}", "how it works:".bold());
    println!("  each entry contains the SHA-256 hash of the previous entry.");
    println!("  modifying any past entry breaks the chain at exactly that point.");
    println!(
        "  {} is detectable by anyone with a copy of the file.",
        "tampering".yellow()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_ts(micros: u64) -> String {
    let secs = (micros / 1_000_000) as i64;
    let nanos = ((micros % 1_000_000) * 1000) as u32;
    match Local.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        _ => format!("ts:{}", micros),
    }
}
