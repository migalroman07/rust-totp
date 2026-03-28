use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};

// Create alias for this stuff.
type HmacSha1 = Hmac<Sha1>;

fn main() -> io::Result<()> {
    println!("==========TOTP Generator==========");

    // Open file and create a buffered reader.
    let file = File::open("my_keys.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut secret = line?;

        // Clean up the key string.
        remove_whitespace(&mut secret);

        // Check if the key has invalid length.
        if secret.is_empty() || secret.len() < 16 {
            println!("Error: invalid secret length.");
            continue;
        }

        // Decode the key with data_encoding crate:
        // if there's no padding, use BASE32_NOPAD,
        // else use BASE32
        let decoded_bytes = match BASE32_NOPAD
            .decode(secret.as_bytes())
            .or_else(|_| BASE32.decode(secret.as_bytes()))
        {
            Ok(bytes) => bytes,
            Err(_) => {
                println!("Error: Invalid Base32 characters.");
                continue;
            }
        };

        // Get current time.
        let sys_time = SystemTime::now();
        let current_time_secs = sys_time.duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Get it and print.
        let decoded_key: u32 = get_totp_code(&decoded_bytes, current_time_secs);

        println!("{:06}", decoded_key);
    }

    Ok(())
}

fn remove_whitespace(s: &mut String) {
    s.retain(|c| !c.is_whitespace());
    s.make_ascii_uppercase();
}

fn get_totp_code(key: &[u8], current_time_secs: u64) -> u32 {
    let current_time_range = current_time_secs / 30;

    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC can take key of any length.");

    mac.update(&current_time_range.to_be_bytes());

    // Calculate HMAC(SHA-1).
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);

    code % 1_000_000
}
