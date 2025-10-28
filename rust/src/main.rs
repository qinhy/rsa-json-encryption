// src/main.rs
mod rjson;

use anyhow::Result;
use rjson::{PEMFileReader, SimpleRSAChunkEncryptor};

fn main() -> Result<()> {
    // (PKCS#8 public and private keys)
    let public_key_path = "../tmp/public_key.pem";
    let private_key_path = "../tmp/private_key.pem";

    // Load keys
    let pub_reader = PEMFileReader::new(public_key_path)?;
    let (e, n) = pub_reader.load_public_pkcs8_key()?;

    let priv_reader = PEMFileReader::new(private_key_path)?;
    let (d, n_priv) = priv_reader.load_private_pkcs8_key()?;

    assert_eq!(n, n_priv, "Public and private moduli differ!");

    // Build encryptor with both keys
    // (we need two owned copies of n; clone once)
    let enc = SimpleRSAChunkEncryptor::new(Some((e, n.clone())), Some((d, n)))?;

    let plaintext = "Hello, RSA encryption with .pem support!";
    println!("Original Plaintext:[{}]", plaintext);

    let encrypted = enc.encrypt_string(plaintext, true)?; // compress = true (like Python)
    println!("\nEncrypted (Base64 encoded):[{}]", encrypted);

    let decrypted = enc.decrypt_string(&encrypted)?;
    println!("\nDecrypted Text:[{}]", decrypted);

    Ok(())
}
