# from https://github.com/qinhy/singleton-key-value-storage.git
import json
import zlib
import base64
import os
import math
import hashlib
from pathlib import Path

class PEMFileReader:
    """
    Minimal PKCS#8 / SubjectPublicKeyInfo PEM reader.

    - Supports:
        * RSA public key in SubjectPublicKeyInfo (PEM with "BEGIN PUBLIC KEY")
        * RSA private key in PKCS#8 (PEM with "BEGIN PRIVATE KEY")
    - Returns:
        * load_public_pkcs8_key()  -> (e, n)
        * load_private_pkcs8_key() -> (d, n)
    """

    def __init__(self, file_path: str | os.PathLike):
        self.file_path = file_path
        self.key_bytes = self._read_pem_file()

    def _read_pem_file(self) -> bytes:
        """Read and decode a PEM file (Base64 between BEGIN/END lines)."""
        with open(self.file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        key_data = "".join(
            line.strip()
            for line in lines
            if "BEGIN" not in line and "END" not in line
        )
        return base64.b64decode(key_data)

    def _parse_asn1_der_element(self, data: bytes, index: int):
        """Parse a single ASN.1 DER element starting at index."""
        tag = data[index]
        index += 1

        # Parse length
        length_byte = data[index]
        index += 1
        if length_byte & 0x80 == 0:
            # Short form length
            length = length_byte & 0x7F
        else:
            # Long form length
            num_length_bytes = length_byte & 0x7F
            length = int.from_bytes(data[index:index + num_length_bytes], "big")
            index += num_length_bytes

        value = data[index:index + length]
        index += length

        return tag, length, value, index

    def _parse_asn1_der_integer(self, data: bytes, index: int):
        """Parse ASN.1 DER INTEGER, return (int_value, new_index)."""
        tag, _, value, index = self._parse_asn1_der_element(data, index)
        if tag != 0x02:
            raise ValueError("Expected INTEGER in ASN.1 structure")
        integer = int.from_bytes(value, "big")
        return integer, index

    def _parse_asn1_der_sequence(self, data: bytes, index: int):
        """Parse ASN.1 DER SEQUENCE, return (value_bytes, new_index)."""
        tag, length, value, index = self._parse_asn1_der_element(data, index)
        if tag != 0x30:
            raise ValueError("Expected SEQUENCE in ASN.1 structure")
        return value, index

    def load_public_pkcs8_key(self):
        """
        Load an RSA public key from a SubjectPublicKeyInfo (PKCS#8-style)
        PEM file, return (e, n).
        """
        data, _ = self._parse_asn1_der_sequence(self.key_bytes, 0)
        index = 0

        # Parse algorithm identifier SEQUENCE and skip it
        _, index = self._parse_asn1_der_sequence(data, index)

        # Parse subjectPublicKey BIT STRING
        tag, _, value, index = self._parse_asn1_der_element(data, index)
        if tag != 0x03:
            raise ValueError("Expected BIT STRING for subjectPublicKey")
        if not value or value[0] != 0x00:
            raise ValueError("Invalid BIT STRING padding")
        public_key_bytes = value[1:]  # skip first padding byte

        # Now parse the inner RSAPublicKey SEQUENCE
        rsa_key_data, _ = self._parse_asn1_der_sequence(public_key_bytes, 0)
        index = 0

        # modulus (n), publicExponent (e)
        n, index = self._parse_asn1_der_integer(rsa_key_data, index)
        e, _ = self._parse_asn1_der_integer(rsa_key_data, index)
        return e, n

    def load_private_pkcs8_key(self):
        """
        Load an RSA private key from a PKCS#8 PEM file, return (d, n).
        """
        data, _ = self._parse_asn1_der_sequence(self.key_bytes, 0)
        index = 0

        # version INTEGER (skip)
        _, index = self._parse_asn1_der_integer(data, index)

        # algorithm identifier SEQUENCE (skip)
        _, index = self._parse_asn1_der_sequence(data, index)

        # privateKey OCTET STRING
        tag, _, private_key_bytes, index = self._parse_asn1_der_element(data, index)
        if tag != 0x04:
            raise ValueError("Expected OCTET STRING for privateKey")

        # RSAPrivateKey SEQUENCE
        rsa_key_data, _ = self._parse_asn1_der_sequence(private_key_bytes, 0)
        index = 0

        # version INTEGER (skip)
        _, index = self._parse_asn1_der_integer(rsa_key_data, index)

        # modulus (n), publicExponent (e), privateExponent (d)
        n, index = self._parse_asn1_der_integer(rsa_key_data, index)
        e, index = self._parse_asn1_der_integer(rsa_key_data, index)
        d, _ = self._parse_asn1_der_integer(rsa_key_data, index)

        # We return (d, n). (e, n) can be reconstructed if needed.
        return d, n

class RSAOAEP:
    """
    Static helper class for RSA-OAEP operations (pure stdlib).

    Provides:
      - i2osp, os2ip
      - mgf1
      - oaep_encode / oaep_decode
      - encrypt_block / decrypt_block (one RSA block)
    """

    @staticmethod
    def i2osp(x: int, x_len: int) -> bytes:
        """Integer-to-Octet-String primitive (PKCS#1)."""
        if x < 0:
            raise ValueError("negative integer")
        if x >= 256 ** x_len:
            raise ValueError("integer too large")
        return x.to_bytes(x_len, "big")

    @staticmethod
    def os2ip(xbytes: bytes) -> int:
        """Octet-String-to-Integer primitive (PKCS#1)."""
        return int.from_bytes(xbytes, "big")

    @staticmethod
    def mgf1(seed: bytes, mask_len: int, hash_func=hashlib.sha256) -> bytes:
        """
        MGF1, as defined in PKCS#1 v2.x.
        Generates mask_len bytes using repeated hashing.
        """
        hLen = hash_func().digest_size
        if mask_len > (1 << 32) * hLen:
            raise ValueError("mask too long")

        out = b""
        for counter in range(0, math.ceil(mask_len / hLen)):
            C = counter.to_bytes(4, "big")
            out += hash_func(seed + C).digest()
        return out[:mask_len]

    @staticmethod
    def oaep_encode(
        message: bytes,
        k: int,
        hash_func=hashlib.sha256,
        label: bytes = b"",
    ) -> bytes:
        """
        OAEP encoding (PKCS#1 v2.x).
        - message: message bytes
        - k: modulus length in bytes
        Returns: EM (encoded message) of length k bytes.
        """
        hLen = hash_func().digest_size
        # mLen <= k - 2*hLen - 2
        if len(message) > k - 2 * hLen - 2:
            raise ValueError("message too long for OAEP")

        lHash = hash_func(label).digest()
        ps_len = k - 2 * hLen - 2 - len(message)
        PS = b"\x00" * ps_len
        DB = lHash + PS + b"\x01" + message  # total length k - hLen - 1

        seed = os.urandom(hLen)
        dbMask = RSAOAEP.mgf1(seed, k - hLen - 1, hash_func)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))

        seedMask = RSAOAEP.mgf1(maskedDB, hLen, hash_func)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))

        EM = b"\x00" + maskedSeed + maskedDB
        if len(EM) != k:
            raise ValueError("internal OAEP error: EM length mismatch")
        return EM

    @staticmethod
    def oaep_decode(
        EM: bytes,
        k: int,
        hash_func=hashlib.sha256,
        label: bytes = b"",
    ) -> bytes:
        """
        OAEP decoding (PKCS#1 v2.x).
        - EM: encoded message of length k
        Returns: message bytes or raises ValueError("decryption error").
        """
        hLen = hash_func().digest_size
        if len(EM) != k:
            raise ValueError("decryption error")

        Y = EM[0]
        maskedSeed = EM[1:1 + hLen]
        maskedDB = EM[1 + hLen:]

        if len(maskedDB) != k - hLen - 1:
            raise ValueError("decryption error")

        seedMask = RSAOAEP.mgf1(maskedDB, hLen, hash_func)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))

        dbMask = RSAOAEP.mgf1(seed, k - hLen - 1, hash_func)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))

        lHash = hash_func(label).digest()
        lHash_prime = DB[:hLen]

        # Basic checks (for serious side-channel resistance you need constant-time)
        if Y != 0 or lHash_prime != lHash:
            raise ValueError("decryption error")

        # DB = lHash || PS (zero bytes) || 0x01 || M
        i = hLen
        while i < len(DB):
            if DB[i] == 0:
                i += 1
                continue
            elif DB[i] == 1:
                break
            else:
                raise ValueError("decryption error")
        else:
            # no 0x01 found
            raise ValueError("decryption error")

        message = DB[i + 1:]
        return message

    @staticmethod
    def encrypt_block(
        message: bytes,
        public_key: tuple[int, int],
        hash_func=hashlib.sha256,
        label: bytes = b"",
    ) -> bytes:
        """
        Encrypt a single message block using RSA-OAEP.
        - message must be <= k - 2*hLen - 2 bytes (OAEP limit).
        - returns ciphertext block of length k bytes.
        """
        e, n = public_key
        k = (n.bit_length() + 7) // 8
        EM = RSAOAEP.oaep_encode(message, k, hash_func, label)
        m_int = RSAOAEP.os2ip(EM)
        if m_int >= n:
            raise ValueError("message representative out of range")
        c_int = pow(m_int, e, n)
        C = RSAOAEP.i2osp(c_int, k)
        return C

    @staticmethod
    def decrypt_block(
        cipher_block: bytes,
        private_key: tuple[int, int],
        hash_func=hashlib.sha256,
        label: bytes = b"",
    ) -> bytes:
        """
        Decrypt a single RSA-OAEP ciphertext block (length k bytes),
        returning the decoded message bytes.
        """
        d, n = private_key
        k = (n.bit_length() + 7) // 8
        if len(cipher_block) != k:
            raise ValueError("ciphertext length mismatch")
        c_int = RSAOAEP.os2ip(cipher_block)
        if c_int >= n:
            raise ValueError("ciphertext representative out of range")
        m_int = pow(c_int, d, n)
        EM = RSAOAEP.i2osp(m_int, k)
        return RSAOAEP.oaep_decode(EM, k, hash_func, label)

class SimpleRSAChunkEncryptor:
    """
    Chunked RSA-OAEP encryptor using only stdlib + RSAOAEP helper.

    - public_key: (e, n) for encryption
    - private_key: (d, n) for decryption
    - hash_name: name of hashlib hash (e.g., "sha256")
    - label: optional OAEP label (must match encode/decode)

    API:
        encrypt_string(plaintext: str, compress: bool = True) -> str
        decrypt_string(encrypted: str) -> str

    Encrypted output is Base64-encoded blocks joined by '|'.
    """

    def __init__(
        self,
        public_key: tuple[int, int] | None = None,
        private_key: tuple[int, int] | None = None,
        hash_name: str = "sha256",
        label: bytes = b"",
    ):
        self.public_key = public_key
        self.private_key = private_key
        try:
            self.hash_func = getattr(hashlib, hash_name)
        except AttributeError:
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")
        self.label = label

        self.k = None
        self.max_msg_len = None

        # derive modulus n from whichever key is provided
        n = None
        if public_key is not None:
            n = public_key[1]
        elif private_key is not None:
            n = private_key[1]

        if n is not None:
            self.k = (n.bit_length() + 7) // 8
            hLen = self.hash_func().digest_size #32bytes
            
            # k_len = [ 0x00 ][ maskedSeed_i (hLen) ][ lHash (hLen) ][ padding(all 0x00) ][ 0x01 ][ msg ]
            self.max_msg_len = self.k - 2 * hLen - 2
            if self.max_msg_len <= 0:
                raise ValueError("Modulus too small for chosen hash")

    def _encrypt_block(self, chunk: bytes) -> bytes:
        if self.public_key is None:
            raise ValueError("Public key required for encryption")
        return RSAOAEP.encrypt_block(chunk, self.public_key, self.hash_func, self.label)

    def _decrypt_block(self, cipher_block: bytes) -> bytes:
        if self.private_key is None:
            raise ValueError("Private key required for decryption")
        return RSAOAEP.decrypt_block(cipher_block, self.private_key, self.hash_func, self.label)

    def encrypt_bytes(self, data: bytes) -> str:
        if self.max_msg_len is None:
            raise ValueError("Public key required for encryption")

        blocks: list[str] = []
        for i in range(0, len(data), self.max_msg_len):
            chunk = data[i : i + self.max_msg_len]
            block = self._encrypt_block(chunk)
            blocks.append(base64.b64encode(block).decode("ascii"))
        return "|".join(blocks)

    def decrypt_bytes(self, encrypted: str) -> bytes:
        if self.private_key is None:
            raise ValueError("Private key required for decryption")
        if not encrypted:
            return b""

        parts = encrypted.split("|")
        out = []
        for part in parts:
            if not part:
                continue
            block = base64.b64decode(part)
            out.append(self._decrypt_block(block))
        return b"".join(out)

    def encrypt_string(self, plaintext: str, compress: bool = True) -> str:
        data = plaintext.encode("utf-8")
        if compress:
            data = zlib.compress(data)
        return self.encrypt_bytes(data)

    def decrypt_string(self, encrypted: str) -> str:
        data = self.decrypt_bytes(encrypted)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return zlib.decompress(data).decode("utf-8")
            except Exception as e:
                raise ValueError("Failed to decode data after all attempts") from e

# --- rJSON convenience wrappers ---------------------------------------------

def dump_rJSONs(data_dict, public_pkcs8_key_path: str) -> str:
    """
    Serialize a Python dict as JSON and encrypt it using RSA-OAEP (chunked).

    - public_pkcs8_key_path: path to PEM with "BEGIN PUBLIC KEY"
    - returns encrypted string (Base64 blocks joined by '|')
    """
    public_key = PEMFileReader(public_pkcs8_key_path).load_public_pkcs8_key()
    encryptor = SimpleRSAChunkEncryptor(public_key=public_key)
    plaintext = json.dumps(data_dict, ensure_ascii=False)
    return encryptor.encrypt_string(plaintext)

def load_rJSONs(encrypted_data: str, private_pkcs8_key_path: str):
    """
    Decrypt an RSA-OAEP-encrypted JSON string and parse it to a dict.

    - private_pkcs8_key_path: path to PEM with "BEGIN PRIVATE KEY"
    """
    private_key = PEMFileReader(private_pkcs8_key_path).load_private_pkcs8_key()
    encryptor = SimpleRSAChunkEncryptor(private_key=private_key)
    plaintext = encryptor.decrypt_string(encrypted_data)
    return json.loads(plaintext)

def dump_rJSON(data_dict, path: str | os.PathLike, public_pkcs8_key_path: str):
    """
    Encrypt dict as JSON with RSA-OAEP and write to file (UTF-8 text).
    """
    enc = dump_rJSONs(data_dict, public_pkcs8_key_path)
    return Path(path).write_text(enc, encoding="utf-8")

def load_rJSON(path: str | os.PathLike, private_pkcs8_key_path: str):
    """
    Read encrypted file and return decrypted dict.
    """
    enc = Path(path).read_text(encoding="utf-8")
    return load_rJSONs(enc, private_pkcs8_key_path)


# Example Usage
def ex1():
    # Example RSA key components (these are just sample values, not secure for actual use)
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate a 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Get public key from the private key
    public_key = private_key.public_key()

    # Extract public exponent (e) and modulus (n) from public key
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n

    # Extract private exponent (d) and modulus (n) from private key
    private_numbers = private_key.private_numbers()
    d = private_numbers.d

    # Now we have public and private key tuples as (e, n) and (d, n)
    public_key_tuple = (e, n)
    private_key_tuple = (d, n)

    print("Public Key:", public_key_tuple)
    print("Private Key:", private_key_tuple)

    # Instantiate the encryptor with the public and private key
    encryptor = SimpleRSAChunkEncryptor(public_key_tuple, private_key_tuple)

    # Encrypt a sample plaintext
    plaintext = "Hello, RSA encryption with chunking and Base64!"
    print(f"Original Plaintext:[{plaintext}]")

    # Encrypt the plaintext
    encrypted_text = encryptor.encrypt_string(plaintext)
    print(f"\nEncrypted (Base64 encoded):[{encrypted_text}]")

    # Decrypt the encrypted text
    decrypted_text = encryptor.decrypt_string(encrypted_text)
    print(f"\nDecrypted Text:[{decrypted_text}]")

def ex2():
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

def ex3():
    # Load keys from .pem files
    public_key_path = './tmp/public_key.pem'
    private_key_path = './tmp/private_key.pem'

    public_key = PEMFileReader(
                    public_key_path).load_public_pkcs8_key()
    private_key = PEMFileReader(
                    private_key_path).load_private_pkcs8_key()

    # Instantiate the encryptor with the loaded keys
    encryptor = SimpleRSAChunkEncryptor(public_key, private_key)

    # Encrypt and decrypt a sample string
    plaintext = "Hello, RSA encryption with .pem support!"
    print(f"Original Plaintext:[{plaintext}]")

    # Encrypt the plaintext
    encrypted_text = encryptor.encrypt_string(plaintext)
    print(f"\nEncrypted (Base64 encoded):[{encrypted_text}]")

    # Decrypt the encrypted text
    decrypted_text = encryptor.decrypt_string(encrypted_text)
    print(f"\nDecrypted Text:[{decrypted_text}]")


def ex4():
    # Load keys from .pem files
    public_key_path = './tmp/public_key.pem'
    private_key_path = './tmp/private_key.pem'

    public_key = PEMFileReader(
                    public_key_path).load_public_pkcs8_key()
    private_key = PEMFileReader(
                    private_key_path).load_private_pkcs8_key()

    image_path = "./tmp/test.png"
    restored_image_path = "./restored_image.png"

    with open(image_path, "rb") as f: img_bytes = f.read()

    img_b64 = base64.b64encode(img_bytes).decode("ascii")
    print(f"Original image bytes: {len(img_bytes)}")
    print(f"Base64 text length  : {len(img_b64)}")

    encryptor = SimpleRSAChunkEncryptor(
        public_key=public_key,private_key=private_key,hash_name="sha256")

    encrypted_text = encryptor.encrypt_string(img_b64, compress=True)
    print(f"Encrypted text length (chars): {len(encrypted_text)}")

    decrypted_b64 = encryptor.decrypt_string(encrypted_text)
    print(f"Decrypted Base64 length       : {len(decrypted_b64)}")

    restored_bytes = base64.b64decode(decrypted_b64.encode("ascii"))

    with open(restored_image_path, "wb") as f: f.write(restored_bytes)
    print(f"Restored image written to: {restored_image_path}")
