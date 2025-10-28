// File: rjson.kt
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater

/* ---------- PEM reader (PKCS#8 public/private) ---------- */

class PEMFileReader(private val filePath: String) {

    private val keyBytes: ByteArray = readPemFile()

    private fun readPemFile(): ByteArray {
        val text = Files.readString(Path.of(filePath))
        val base64Body = text
            .lineSequence()
            .filter { !it.contains("BEGIN") && !it.contains("END") }
            .joinToString("") { it.trim() }
        return Base64.getMimeDecoder().decode(base64Body)
    }

    /** Load (e, n) from a PKCS#8 public key (SubjectPublicKeyInfo/X.509). */
    fun loadPublicPkcs8Key(): Pair<BigInteger, BigInteger> {
        val spec = X509EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        val pub = kf.generatePublic(spec) as RSAPublicKey
        val e = pub.publicExponent
        val n = pub.modulus
        return e to n
    }

    /** Load (d, n) from a PKCS#8 private key. */
    fun loadPrivatePkcs8Key(): Pair<BigInteger, BigInteger> {
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        val priv = kf.generatePrivate(spec) as RSAPrivateKey
        val d = priv.privateExponent
        val n = priv.modulus
        return d to n
    }
}

/* ---------- Simple chunked RSA (no padding), zlib optional ---------- */

class SimpleRSAChunkEncryptor(
    private val publicKey: Pair<BigInteger, BigInteger>? = null,   // (e, n)
    private val privateKey: Pair<BigInteger, BigInteger>? = null   // (d, n)
) {
    private val chunkSizeBytes: Int? = publicKey?.second?.bitLength()?.div(8)?.also {
        require(it > 0) { "The modulus 'n' is too small. Please use a larger key size." }
    }

    fun encryptString(plaintext: String, compress: Boolean = true): String {
        val size = chunkSizeBytes ?: error("Public key required for encryption.")
        val e = publicKey!!.first
        val n = publicKey.second

        // 1) Prepare data
        var data = plaintext.toByteArray(StandardCharsets.UTF_8)
        if (compress) data = zlibCompress(data)

        // The Python code uses (modulusByteLen - 1) per chunk
        val perChunk = size - 1
        val chunks = data.asList().chunked(perChunk).map { it.toByteArray() }

        // 2) Encrypt each chunk using the "0x1 + hex" trick
        val modulusByteLen = bytesForModulus(n)
        val encoder = Base64.getEncoder()

        val encryptedChunks = chunks.map { chunk ->
            val chunkHex = chunk.toHex()
            val chunkInt = BigInteger("1$chunkHex", 16)  // equivalent to Python's int('0x1' + hex, 16)
            val encryptedInt = chunkInt.modPow(e, n)
            val padded = toFixedLength(encryptedInt, modulusByteLen)
            encoder.encodeToString(padded)
        }

        // 3) Join with '|'
        return encryptedChunks.joinToString("|")
    }

    fun decryptString(encryptedData: String): String {
        val priv = privateKey ?: error("Private key required for decryption.")
        val d = priv.first
        val n = priv.second

        val decoder = Base64.getDecoder()

        // 1) Decode and decrypt each chunk
        val decryptedPieces: List<ByteArray> = encryptedData.split("|").filter { it.isNotEmpty() }.map { b64 ->
            val encBytes = decoder.decode(b64)
            val encInt = BigInteger(1, encBytes)
            val decInt = encInt.modPow(d, n)
            // Python: hex(decInt)[3:]  -> drop "0x1" and keep the original chunk hex
            val hexWithLeading1 = decInt.toString(16)
            require(hexWithLeading1.startsWith("1")) {
                "Decryption failed: expected leading '1' nibble, got: $hexWithLeading1"
            }
            val originalHex = hexWithLeading1.drop(1).let {
                if (it.length % 2 == 1) "0$it" else it  // just in case
            }
            originalHex.hexToBytes()
        }

        // 2) Concatenate
        val bos = java.io.ByteArrayOutputStream()
        decryptedPieces.forEach { bos.write(it) }
        val data = bos.toByteArray()
        
        // 3) Try UTF-8 first, else try zlib-decompress then UTF-8 (matches Python order)
        return try {
                zlibDecompress(data).toString(java.nio.charset.StandardCharsets.UTF_8)
        } catch (_: Exception) {
            try {
                data.toString(java.nio.charset.StandardCharsets.UTF_8)
            } catch (e: Exception) {
                throw IllegalArgumentException("Failed to decode data after all attempts.", e)
            }
        }
    }

    private fun bytesForModulus(n: BigInteger): Int {
        // Closer to Python's floor bitLength/8; if you prefer exact byte length, use ceil: (bitLen + 7) / 8
        return n.bitLength() / 8
    }

    private fun toFixedLength(x: BigInteger, len: Int): ByteArray {
        var raw = x.toByteArray() // two's complement, may have an extra sign byte
        if (raw.size == len) return raw
        if (raw.size == len + 1 && raw[0] == 0.toByte()) {
            // Drop sign byte
            raw = raw.copyOfRange(1, raw.size)
        }
        if (raw.size > len) {
            // Very rare if modulus byte length estimate was off
            return raw.copyOfRange(raw.size - len, raw.size)
        }
        // Left-pad with zeros
        val out = ByteArray(len)
        System.arraycopy(raw, 0, out, len - raw.size, raw.size)
        return out
    }

    private fun zlibCompress(input: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, /*nowrap=*/false)
        deflater.setInput(input)
        deflater.finish()
        val bos = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        while (!deflater.finished()) {
            val n = deflater.deflate(buf)
            bos.write(buf, 0, n)
        }
        deflater.end()
        return bos.toByteArray()
    }

    private fun zlibDecompress(input: ByteArray): ByteArray {
        val inflater = Inflater(/*nowrap=*/false)
        inflater.setInput(input)
        val bos = ByteArrayOutputStream()
        val buf = ByteArray(1024)
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            if (n == 0 && inflater.needsInput()) break
            bos.write(buf, 0, n)
        }
        inflater.end()
        return bos.toByteArray()
    }
}

/* ---------- Helpers & convenience funcs (rJSON-style) ---------- */

/** Dump a JSON string through RSA (public key) — mirrors dump_rJSONs in Python. */
fun dumpRJSONs(jsonString: String, publicPkcs8KeyPath: String): String {
    val (e, n) = PEMFileReader(publicPkcs8KeyPath).loadPublicPkcs8Key()
    val encryptor = SimpleRSAChunkEncryptor(publicKey = e to n)
    return encryptor.encryptString(jsonString)
}

/** Load (decrypt) a JSON string with RSA (private key) — mirrors load_rJSONs in Python. */
fun loadRJSONs(encrypted: String, privatePkcs8KeyPath: String): String {
    val (d, n) = PEMFileReader(privatePkcs8KeyPath).loadPrivatePkcs8Key()
    val encryptor = SimpleRSAChunkEncryptor(privateKey = d to n)
    return encryptor.decryptString(encrypted)
}

/** Write encrypted JSON to a file — mirrors dump_rJSON in Python. */
fun dumpRJSON(jsonString: String, path: String, publicPkcs8KeyPath: String) {
    val encrypted = dumpRJSONs(jsonString, publicPkcs8KeyPath)
    Files.writeString(Path.of(path), encrypted)
}

/** Read and decrypt JSON from a file — mirrors load_rJSON in Python. */
fun loadRJSON(path: String, privatePkcs8KeyPath: String): String {
    val content = Files.readString(Path.of(path))
    return loadRJSONs(content, privatePkcs8KeyPath)
}

/* ---------- Demo matching ex3() ---------- */

fun ex3() {
    val publicKeyPath = "../tmp/public_key.pem"
    val privateKeyPath = "../tmp/private_key.pem"

    val (e, nPub) = PEMFileReader(publicKeyPath).loadPublicPkcs8Key()
    val (d, nPriv) = PEMFileReader(privateKeyPath).loadPrivatePkcs8Key()

    val encryptor = SimpleRSAChunkEncryptor(publicKey = e to nPub, privateKey = d to nPriv)

    val plaintext = "Hello, RSA encryption with .pem support!"
    println("Original Plaintext: [$plaintext]")

    val encrypted = encryptor.encryptString(plaintext)
    println("\nEncrypted (Base64 encoded): [$encrypted]")

    val decrypted = encryptor.decryptString(encrypted)
    println("\nDecrypted Text: [$decrypted]")
}

/* ---------- Byte/hex utilities ---------- */

private fun ByteArray.toHex(): String {
    val sb = StringBuilder(this.size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        if (v < 16) sb.append('0')
        sb.append(v.toString(16))
    }
    return sb.toString()
}

private fun String.hexToBytes(): ByteArray {
    val s = if (this.length % 2 == 0) this else "0$this"
    val out = ByteArray(s.length / 2)
    var i = 0
    while (i < s.length) {
        out[i / 2] = ((s[i].digitToInt(16) shl 4) or s[i + 1].digitToInt(16)).toByte()
        i += 2
    }
    return out
}

/* ---------- Optionally, run ex3() ---------- */
// fun main() = ex3()
// kotlinc rjson.kt -include-runtime -d rjson.jar && java -jar rjson.jar