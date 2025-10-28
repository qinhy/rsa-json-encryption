use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::{fs, io::{Read, Write}, path::{Path, PathBuf}};

/// Minimal PEM reader + DER helper, mirroring the Python.
pub struct PEMFileReader {
    file_path: PathBuf,
    key_bytes: Vec<u8>,
}

impl PEMFileReader {
    pub fn new<P: Into<PathBuf>>(file_path: P) -> Result<Self> {
        let file_path = file_path.into();
        let key_bytes = Self::read_pem_file(&file_path)?;
        Ok(Self { file_path, key_bytes })
    }

    fn read_pem_file(path: &Path) -> Result<Vec<u8>> {
        let pem = fs::read_to_string(path)
            .with_context(|| format!("Failed to read PEM file: {}", path.display()))?;
        let mut body = String::new();
        for line in pem.lines() {
            let l = line.trim();
            if !(l.contains("BEGIN") || l.contains("END") || l.is_empty()) {
                body.push_str(l);
            }
        }
        let der = B64
            .decode(body.as_bytes())
            .context("Base64 decode of PEM body failed")?;
        Ok(der)
    }

    /// Parse a DER element: returns (tag, length, value, next_index)
    fn parse_asn1_der_element(data: &[u8], mut index: usize) -> Result<(u8, usize, Vec<u8>, usize)> {
        if index >= data.len() { bail!("DER: out of bounds"); }
        let tag = data[index];
        index += 1;

        if index >= data.len() { bail!("DER: missing length"); }
        let length_byte = data[index];
        index += 1;

        let length: usize = if (length_byte & 0x80) == 0 {
            (length_byte & 0x7F) as usize
        } else {
            let num_length_bytes = (length_byte & 0x7F) as usize;
            if num_length_bytes == 0 { bail!("DER: indefinite length not allowed in DER"); }
            if index + num_length_bytes > data.len() { bail!("DER: length bytes OOB"); }
            let mut len: usize = 0;
            for &b in &data[index..index+num_length_bytes] {
                len = (len << 8) | (b as usize);
            }
            index += num_length_bytes;
            len
        };

        if index + length > data.len() { bail!("DER: value OOB"); }
        let value = data[index..index+length].to_vec();
        index += length;
        Ok((tag, length, value, index))
    }

    fn parse_asn1_der_integer(data: &[u8], index: usize) -> Result<(BigUint, usize)> {
        let (tag, _len, value, next) = Self::parse_asn1_der_element(data, index)?;
        if tag != 0x02 { bail!("Expected INTEGER"); }
        // INTEGER may have a leading 0x00 for sign; BigUint handles that fine.
        Ok((BigUint::from_bytes_be(&value), next))
    }

    fn parse_asn1_der_sequence(data: &[u8], index: usize) -> Result<(Vec<u8>, usize)> {
        let (tag, _len, value, next) = Self::parse_asn1_der_element(data, index)?;
        if tag != 0x30 { bail!("Expected SEQUENCE"); }
        Ok((value, next))
    }

    /// Load (e, n) from SubjectPublicKeyInfo (PKCS#8 public)
    pub fn load_public_pkcs8_key(&self) -> Result<(BigUint, BigUint)> {
        // Outer SEQUENCE of SubjectPublicKeyInfo
        let (spki, _) = Self::parse_asn1_der_sequence(&self.key_bytes, 0)?;
        let mut idx = 0;

        // AlgorithmIdentifier (skip)
        let (_algid, next) = Self::parse_asn1_der_sequence(&spki, idx)?;
        idx = next;

        // BIT STRING of public key
        let (tag, _len, bitstring, next) = Self::parse_asn1_der_element(&spki, idx)?;
        idx = next;
        if tag != 0x03 { bail!("Expected BIT STRING for subjectPublicKey"); }
        if bitstring.is_empty() || bitstring[0] != 0x00 {
            bail!("Invalid BIT STRING padding");
        }
        let public_key_bytes = &bitstring[1..];

        // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
        let (rsa_seq, _) = Self::parse_asn1_der_sequence(public_key_bytes, 0)?;
        let mut rdx = 0;
        let (n, nextn) = Self::parse_asn1_der_integer(&rsa_seq, rdx)?;
        rdx = nextn;
        let (e, _nexte) = Self::parse_asn1_der_integer(&rsa_seq, rdx)?;

        // Return (e, n) like Python
        Ok((e, n))
    }

    /// Load (d, n) from PrivateKeyInfo (PKCS#8 private)
    pub fn load_private_pkcs8_key(&self) -> Result<(BigUint, BigUint)> {
        // PrivateKeyInfo ::= SEQUENCE
        let (pki, _) = Self::parse_asn1_der_sequence(&self.key_bytes, 0)?;
        let mut idx = 0;

        // version INTEGER (skip)
        let (_ver, next) = Self::parse_asn1_der_integer(&pki, idx)?;
        idx = next;

        // AlgorithmIdentifier (skip)
        let (_algid, next) = Self::parse_asn1_der_sequence(&pki, idx)?;
        idx = next;

        // privateKey OCTET STRING
        let (tag, _len, pk_octets, next) = Self::parse_asn1_der_element(&pki, idx)?;
        idx = next;
        if tag != 0x04 { bail!("Expected OCTET STRING for privateKey"); }

        // RSAPrivateKey ::= SEQUENCE { version, n, e, d, ... }
        let (rsa_priv_seq, _) = Self::parse_asn1_der_sequence(&pk_octets, 0)?;
        let mut rdx = 0;

        // version (skip)
        let (_pver, next) = Self::parse_asn1_der_integer(&rsa_priv_seq, rdx)?;
        rdx = next;

        // n, e, d
        let (n, next) = Self::parse_asn1_der_integer(&rsa_priv_seq, rdx)?;
        rdx = next;
        let (_e, next) = Self::parse_asn1_der_integer(&rsa_priv_seq, rdx)?;
        rdx = next;
        let (d, _next) = Self::parse_asn1_der_integer(&rsa_priv_seq, rdx)?;

        // Return (d, n) like Python
        Ok((d, n))
    }
}

pub struct SimpleRSAChunkEncryptor {
    public_key: Option<(BigUint, BigUint)>, // (e, n)
    private_key: Option<(BigUint, BigUint)>, // (d, n)
    chunk_modulus_bytes: Option<usize>,      // bytes in modulus (n)
}

impl SimpleRSAChunkEncryptor {
    pub fn new(public_key: Option<(BigUint, BigUint)>, private_key: Option<(BigUint, BigUint)>) -> Result<Self> {
        let chunk_modulus_bytes = public_key.as_ref().map(|(_e, n)| {
            let bits = n.bits();
            (bits + 7) as usize / 8
        });
        if let Some(sz) = chunk_modulus_bytes {
            if sz == 0 {
                bail!("The modulus 'n' is too small. Please use a larger key size.");
            }
        }
        Ok(Self { public_key, private_key, chunk_modulus_bytes })
    }

    /// Encrypt a UTF-8 string, optionally compressing first (default true like Python).
    pub fn encrypt_string(&self, plaintext: &str, compress: bool) -> Result<String> {
        let (e, n) = self
            .public_key
            .as_ref()
            .ok_or_else(|| anyhow!("Public key required for encryption."))?;
        let modulus_bytes = self
            .chunk_modulus_bytes
            .ok_or_else(|| anyhow!("Internal: missing modulus size"))?;
        let chunk_size = modulus_bytes - 1; // same as Python

        // Step 1: compress or not
        let data: Vec<u8> = if compress {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(plaintext.as_bytes())?;
            enc.finish()?
        } else {
            plaintext.as_bytes().to_vec()
        };

        // Step 2: split
        let mut encrypted_chunks: Vec<String> = Vec::new();
        for chunk in data.chunks(chunk_size) {
            // b. Build BigUint equivalent to Python's int('0x1' + chunk.hex(), 16):
            //     (1 << (8*len)) + int_from_bytes(chunk)
            let shift = 8 * chunk.len();
            let prefix = BigUint::one() << shift;
            let chunk_int = prefix + BigUint::from_bytes_be(chunk);

            // c. Encrypt: pow(chunk_int, e, n)
            let encrypted = chunk_int.modpow(e, n);

            // d. Convert to bytes padded to modulus length
            let mut enc_bytes = encrypted.to_bytes_be();
            if enc_bytes.len() > modulus_bytes {
                bail!("Encrypted integer larger than modulus byte length.");
            }
            if enc_bytes.len() < modulus_bytes {
                let mut padded = vec![0u8; modulus_bytes - enc_bytes.len()];
                padded.extend_from_slice(&enc_bytes);
                enc_bytes = padded;
            }

            // e. Base64 encode those bytes
            let b64 = B64.encode(enc_bytes);
            encrypted_chunks.push(b64);
        }

        // Step 4: join with '|'
        Ok(encrypted_chunks.join("|"))
    }

    /// Decrypt a Base64+pipe-joined payload back to UTF-8 (tries plain UTF-8, then zlib).
    pub fn decrypt_string(&self, encrypted_data: &str) -> Result<String> {
        let (d, n) = self
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("Private key required for decryption."))?;
        let mut out: Vec<u8> = Vec::new();

        for chunk_b64 in encrypted_data.split('|') {
            let enc_bytes = B64.decode(chunk_b64.as_bytes())
                .with_context(|| "Base64 decode failed for a chunk")?;
            let c = BigUint::from_bytes_be(&enc_bytes);
            let m = c.modpow(d, n);

            // Python: hex(m)[3:] removes "0x1" prefix (first nibble '1').
            let mut hex_str = m.to_str_radix(16);
            if hex_str.is_empty() || !hex_str.starts_with('1') {
                bail!("Decryption failed: missing leading '1' nibble in plaintext block.");
            }
            hex_str.remove(0); // drop the leading '1' nibble

            // Ensure even-length hex to decode into bytes
            if hex_str.len() % 2 != 0 {
                hex_str = format!("0{hex_str}");
            }

            let bytes = hex::decode(&hex_str).context("Failed to hex-decode decrypted chunk")?;
            out.extend_from_slice(&bytes);
        }

        // Try UTF-8; if not, try zlib decompress then UTF-8
        match String::from_utf8(out.clone()) {
            Ok(s) => Ok(s),
            Err(_) => {
                let mut dec = ZlibDecoder::new(&out[..]);
                let mut buf = Vec::new();
                dec.read_to_end(&mut buf)
                    .context("Failed to zlib-decompress decrypted data")?;
                String::from_utf8(buf).context("Decompressed data is not valid UTF-8")
            }
        }
    }
}

/// Dump JSON to an encrypted string using a public PKCS#8 PEM.
pub fn dump_rjsons<T: serde::Serialize>(data: &T, public_pkcs8_key_path: impl AsRef<Path>) -> Result<String> {
    let reader = PEMFileReader::new(public_pkcs8_key_path.as_ref())?;
    let (e, n) = reader.load_public_pkcs8_key()?;
    let enc = SimpleRSAChunkEncryptor::new(Some((e, n)), None)?;
    let json = serde_json::to_string(data)?;
    enc.encrypt_string(&json, true)
}

/// Load JSON from an encrypted string using a private PKCS#8 PEM.
pub fn load_rjsons<T: serde::de::DeserializeOwned>(encrypted: &str, private_pkcs8_key_path: impl AsRef<Path>) -> Result<T> {
    let reader = PEMFileReader::new(private_pkcs8_key_path.as_ref())?;
    let (d, n) = reader.load_private_pkcs8_key()?;
    let enc = SimpleRSAChunkEncryptor::new(None, Some((d, n)))?;
    let plaintext = enc.decrypt_string(encrypted)?;
    let value = serde_json::from_str::<T>(&plaintext)?;
    Ok(value)
}

/// Write encrypted JSON to a file.
pub fn dump_rjson<T: serde::Serialize>(data: &T, path: impl AsRef<Path>, public_pkcs8_key_path: impl AsRef<Path>) -> Result<()> {
    let s = dump_rjsons(data, public_pkcs8_key_path)?;
    fs::write(path.as_ref(), s).with_context(|| format!("Write failed: {}", path.as_ref().display()))?;
    Ok(())
}

/// Read encrypted JSON from a file.
pub fn load_rjson<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>, private_pkcs8_key_path: impl AsRef<Path>) -> Result<T> {
    let s = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Read failed: {}", path.as_ref().display()))?;
    load_rjsons(&s, private_pkcs8_key_path)
}

/* -------------------------
   Example usage (mirrors ex3)
   -------------------------

use std::collections::HashMap;

pub fn ex3() -> Result<()> {
    // Paths to existing PKCS#8 keys (public: SubjectPublicKeyInfo, private: PrivateKeyInfo)
    let public_key_path = "./tmp/public_key.pem";
    let private_key_path = "./tmp/private_key.pem";

    // Load keys
    let pub_reader = PEMFileReader::new(public_key_path)?;
    let (e, n) = pub_reader.load_public_pkcs8_key()?;

    let priv_reader = PEMFileReader::new(private_key_path)?;
    let (d, n_priv) = priv_reader.load_private_pkcs8_key()?;
    assert_eq!(n, n_priv);

    // Instantiate encryptor with both keys (optional)
    let enc = SimpleRSAChunkEncryptor::new(Some((e, n)), Some((d, n_priv)))?;

    let plaintext = "Hello, RSA encryption with .pem support!";
    println!("Original Plaintext:[{plaintext}]");

    let encrypted = enc.encrypt_string(plaintext, true)?;
    println!("Encrypted (Base64 encoded):[{encrypted}]");

    let decrypted = enc.decrypt_string(&encrypted)?;
    println!("Decrypted Text:[{decrypted}]");

    Ok(())
}

*/
