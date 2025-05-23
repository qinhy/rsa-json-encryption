# 🔐 RSA JSON Encryption with PEM Key Support

This Python module provides a lightweight RSA encryption/decryption utility for string and JSON data, using manually parsed PEM-formatted PKCS#8 keys. It includes chunked encryption for large strings and Base64-encoded output for easy transport.

## Features

- 📄 Supports RSA public and private keys in **PKCS#8 PEM format**
- 🧩 Chunk-based encryption to handle large plaintexts
- 🔐 Manual ASN.1 DER parsing of PEM-encoded keys (no heavy libraries needed for key parsing)
- 🧾 Simple JSON encryption and file utilities
- 🛠️ Pure Python implementation for educational clarity

---

## 📦 Installation

Requires Python 3.7+

---

## 🚀 Quick Start

### 1. Generate Keys
This lib is no need for pip.
but **Generate Keys** will needed.

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate a 2048-bit RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Export the private key in PKCS#8 format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # Use a password here for encryption, if desired
)
with open("private_key.pem", "wb") as private_file:
    private_file.write(private_key_pem)

# Export the public key in PEM format
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("public_key.pem", "wb") as public_file:
    public_file.write(public_key_pem)

print("Keys have been generated and saved as 'private_key.pem' and 'public_key.pem'.")

```

This will generate:

* `public_key.pem`
* `private_key.pem`

### 2. Encrypt and Decrypt a String (`ex3()`)

```python
from rjson import ex3
ex3()
```

### 3. Encrypt and Save JSON to File

```python
from rjson import dump_RSA

data = {'message': 'This is confidential'}
dump_RSA(data, 'data.rjson', 'public_key.pem')
```

### 4. Load and Decrypt JSON from File

```python
from rjson import load_RSA

decrypted_data = load_RSA('data.rjson', 'private_key.pem')
print(decrypted_data)
```

---

## 📚 API Overview

### PEMFileReader

Low-level reader for PKCS#8 `.pem` files.

```python
PEMFileReader("public_key.pem").load_public_pkcs8_key()  # Returns (e, n)
PEMFileReader("private_key.pem").load_private_pkcs8_key()  # Returns (d, n)
```

---

### SimpleRSAChunkEncryptor

```python
SimpleRSAChunkEncryptor(public_key=(e, n), private_key=(d, n))

encrypt_string("text") → Base64 encoded string  
decrypt_string("Base64 string") → Original plaintext
```

---

### Utilities

```python
dump_RSA(dict_data, path, public_key_path)
load_RSA(path, private_key_path)
```

---

## 🧪 Example

```python
plaintext = "Hello, secure world!"

# Encrypt with public key
encryptor = SimpleRSAChunkEncryptor(public_key=(e, n))
encrypted = encryptor.encrypt_string(plaintext)

# Decrypt with private key
decryptor = SimpleRSAChunkEncryptor(private_key=(d, n))
decrypted = decryptor.decrypt_string(encrypted)
```

---

## 🔒 Disclaimer

This library is built for educational and experimental purposes. Do **not** use it in production environments without security reviews. For secure and battle-tested cryptographic implementations, consider using [PyCryptodome](https://www.pycryptodome.org/) or [Cryptography](https://cryptography.io/).

---

## 📄 License

MIT License © 2025 HUANGYI QIN

```

---

Let me know if you’d like to customize the name, description, or examples to match your actual file/module name before you add this to your repository.
```
