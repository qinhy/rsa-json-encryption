# 🔐 RSA JSON Encryption with PEM Key Support

**A lightweight, pure Python utility for encrypting and decrypting JSON and string data using RSA keys in PKCS#8 PEM format.**

---

## ⚠️ Disclaimer
This library is for educational and experimental use only. **Do not use in production** without a thorough security review. For robust cryptography, use [PyCryptodome](https://www.pycryptodome.org/) or [Cryptography](https://cryptography.io/).

---

## 📦 Features
- Supports RSA public/private keys in **PKCS#8 PEM** format
- Chunk-based encryption for large data
- Manual ASN.1 DER parsing (no heavy dependencies for key parsing)
- Simple JSON encryption/decryption and file utilities
- Pure Python, easy to read and modify

---

## 📚 Table of Contents
- [Installation](#installation)
- [Key Generation](#key-generation)
- [Quick Start](#quick-start)
- [API Overview](#api-overview)
- [Examples](#examples)
- [License](#license)

---

## 🛠️ Installation
- Python 3.7+
- No pip install needed for this module (just copy `rjson.py`)
- For key generation, install `cryptography`:
  ```bash
  pip install cryptography
  ```

---

## 🔑 Key Generation
Generate RSA keys using Python's `cryptography` library:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("private_key.pem", "wb") as f:
    f.write(private_key_pem)

public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("public_key.pem", "wb") as f:
    f.write(public_key_pem)
```

---

## 🚀 Quick Start

### Encrypt and Save JSON to File
```python
from rjson import dump_rJSON

data = {'message': 'This is confidential'}
dump_rJSON(data, 'data.rjson', 'public_key.pem')
```

### Load and Decrypt JSON from File
```python
from rjson import load_rJSONs

decrypted_data = load_rJSONs(open('data.rjson').read(), 'private_key.pem')
print(decrypted_data)
```

### Encrypt and Decrypt a String
```python
from rjson import SimpleRSAChunkEncryptor, PEMFileReader

# Load keys
public_key = PEMFileReader('public_key.pem').load_public_pkcs8_key()
private_key = PEMFileReader('private_key.pem').load_private_pkcs8_key()

# Encrypt
encryptor = SimpleRSAChunkEncryptor(public_key=public_key)
encrypted = encryptor.encrypt_string("Hello, secure world!")

# Decrypt
decryptor = SimpleRSAChunkEncryptor(private_key=private_key)
decrypted = decryptor.decrypt_string(encrypted)
print(decrypted)
```

---

## 🧩 API Overview

### PEMFileReader
- `PEMFileReader(path).load_public_pkcs8_key()` → `(e, n)`
- `PEMFileReader(path).load_private_pkcs8_key()` → `(d, n)`

### SimpleRSAChunkEncryptor
- `SimpleRSAChunkEncryptor(public_key=(e, n), private_key=(d, n))`
- `encrypt_string(text)` → Base64 string
- `decrypt_string(base64_string)` → Plaintext

### Utilities
- `dump_rJSON(dict_data, path, public_key_path)`
- `load_rJSONs(encrypted_data, private_key_path)`

---

## 🧪 Example Output

**Encrypted:**
```
U2FsdGVkX1+...|U2FsdGVkX2...
```
**Decrypted:**
```
{"message": "This is confidential"}
```

---

## 📄 License
MIT License © 2025 HUANGYI QIN