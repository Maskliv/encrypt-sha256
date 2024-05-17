use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::env;
fn main() {
    // Collect the command line arguments
    let args: Vec<String> = env::args().collect();
    // Check if the correct number of arguments were provided
    if args.len() != 3 {
        eprintln!("Usage: {} <password> <salt>", "encrypt-sha256");
        return;
    }
     // Extract the password and salt from the arguments
    let password = &args[1];
    let salt = &args[2];
    // Concatenate password and salt
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());

    // Calculate the SHA-256 hash
    let result = hasher.finalize();

    // Encode the hash as a base64 string
    let base64_result = STANDARD.encode(&result);
    //encode(result);

    // Print the base64 string
    println!("{}", base64_result);
}
