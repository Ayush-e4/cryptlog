use cryptlog::Log;

fn main() {
    // --- create a fresh log ---
    let path = "audit.clog";
    let mut log = Log::open(path).expect("failed to open log");

    println!("=== appending entries ===");
    log.append("user:42 logged in from 192.168.1.1").unwrap();
    log.append("user:42 deleted invoice:991").unwrap();
    log.append("user:99 modified student:101 fee:5000->4500")
        .unwrap();
    log.append("user:01 exported all records").unwrap();

    println!("entries written: {}", log.entry_count());
    println!("last hash: {}", hex(log.last_hash()));

    // --- verify the chain is intact ---
    println!("\n=== verifying chain ===");
    match log.verify() {
        Ok(_) => println!("✓ chain intact — nothing tampered"),
        Err(e) => println!("✗ chain broken: {:?}", e),
    }

    // --- read all entries back ---
    println!("\n=== reading all entries ===");
    let entries = log.read_all().unwrap();
    for (i, entry) in entries.iter().enumerate() {
        println!(
            "[{}] ts={} data={:?} hash={}",
            i,
            entry.timestamp,
            String::from_utf8_lossy(&entry.data),
            hex(&entry.hash),
        );
    }

    // --- now tamper with the file directly and re-verify ---
    println!("\n=== tampering with file ===");
    tamper(path);

    match log.verify() {
        Ok(_) => println!("✓ chain intact (this should not happen)"),
        Err(e) => println!("✗ caught tampering: {:?}", e),
    }

    // cleanup
    std::fs::remove_file(path).unwrap();
}

// brute force flip a byte in the middle of the file to simulate tampering
fn tamper(path: &str) {
    let mut bytes = std::fs::read(path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF; // flip all bits of one byte
    std::fs::write(path, bytes).unwrap();
    println!("flipped byte at offset {}", mid);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
