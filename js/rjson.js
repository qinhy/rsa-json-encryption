// JavaScript version of rjson.ts

// Dynamic imports based on environment
let fs;
let pako;
let Buffer;

if (typeof window === 'undefined') {
    // Node.js environment
    fs = require('fs');
    pako = require('pako');
    Buffer = global.Buffer;
} else {
    // Browser environment
    fs = null; // Browser doesn't have direct file system access
    pako = window.pako;
    Buffer = window.Buffer;
}

class PEMFileReader {
    constructor(filePath) {
        this.filePath = filePath;
    }

    readPEMFile() {
        if (!fs) {
            throw new Error('File system operations are not available in this environment.');
        }

        const pemContent = fs.readFileSync(this.filePath, 'utf-8');
        const base64Content = pemContent
            .replace(/-----BEGIN [^-]+-----/, '')
            .replace(/-----END [^-]+-----/, '')
            .replace(/\s+/g, '');

        return Buffer.from(base64Content, 'base64');
    }

    parseASN1DERElement(buffer, offset = 0) {
        // Parse ASN.1 DER element and return its value and the next offset
        const tag = buffer[offset];
        offset += 1;

        // Parse length
        let length = buffer[offset];
        offset += 1;

        if (length & 0x80) {
            // Length is encoded in multiple bytes
            const lengthBytes = length & 0x7F;
            length = 0;
            for (let i = 0; i < lengthBytes; i++) {
                length = (length << 8) | buffer[offset];
                offset += 1;
            }
        }

        // Extract value based on tag
        let value;
        if (tag === 0x02) { // INTEGER
            value = buffer.subarray(offset, offset + length);
        } else if (tag === 0x03) { // BIT STRING
            // Skip the first byte (unused bits count) for bit strings
            value = buffer.subarray(offset + 1, offset + length);
        } else if (tag === 0x04) { // OCTET STRING
            value = buffer.subarray(offset, offset + length);
        } else if (tag === 0x30) { // SEQUENCE
            value = buffer.subarray(offset, offset + length);
        } else {
            value = buffer.subarray(offset, offset + length);
        }

        return { value, nextOffset: offset + length };
    }

    loadPublicPkcs8Key() {
        const derBuffer = this.readPEMFile();
        
        // Parse the outer SEQUENCE
        const { value: outerSequence } = this.parseASN1DERElement(derBuffer);
        
        // Parse the inner SEQUENCE (algorithm identifier)
        const { nextOffset: afterAlgorithm } = this.parseASN1DERElement(outerSequence);
        
        // Parse the BIT STRING containing the public key
        const { value: publicKeyBitString } = this.parseASN1DERElement(outerSequence, afterAlgorithm);
        
        // Parse the public key SEQUENCE
        const { value: publicKeySequence } = this.parseASN1DERElement(publicKeyBitString);
        
        // Parse modulus (n)
        const { value: modulusBuffer, nextOffset: afterModulus } = this.parseASN1DERElement(publicKeySequence);
        
        // Parse exponent (e)
        const { value: exponentBuffer } = this.parseASN1DERElement(publicKeySequence, afterModulus);
        
        // Convert to BigInt
        const n = this.bufferToBigInt(modulusBuffer);
        const e = this.bufferToBigInt(exponentBuffer);
        
        return [e, n];
    }

    loadPrivatePkcs8Key() {
        const derBuffer = this.readPEMFile();
        
        // Parse the outer SEQUENCE
        const { value: outerSequence } = this.parseASN1DERElement(derBuffer);
        
        // Skip version
        const { nextOffset: afterVersion } = this.parseASN1DERElement(outerSequence);
        
        // Skip algorithm identifier SEQUENCE
        const { nextOffset: afterAlgorithm } = this.parseASN1DERElement(outerSequence, afterVersion);
        
        // Parse the OCTET STRING containing the private key
        const { value: privateKeyOctetString } = this.parseASN1DERElement(outerSequence, afterAlgorithm);
        
        // Parse the private key SEQUENCE
        const { value: privateKeySequence } = this.parseASN1DERElement(privateKeyOctetString);
        
        // Skip version
        const { nextOffset: afterPrivateKeyVersion } = this.parseASN1DERElement(privateKeySequence);
        
        // Skip modulus (n)
        const { nextOffset: afterModulus } = this.parseASN1DERElement(privateKeySequence, afterPrivateKeyVersion);
        
        // Skip public exponent (e)
        const { nextOffset: afterPublicExponent } = this.parseASN1DERElement(privateKeySequence, afterModulus);
        
        // Parse private exponent (d)
        const { value: privateExponentBuffer } = this.parseASN1DERElement(privateKeySequence, afterPublicExponent);
        
        // Get modulus from public key
        const [_, n] = this.loadPublicPkcs8Key();
        
        // Convert to BigInt
        const d = this.bufferToBigInt(privateExponentBuffer);
        
        return [d, n];
    }

    bufferToBigInt(buffer) {
        // Convert buffer to hex string and then to BigInt
        return BigInt('0x' + Buffer.from(buffer).toString('hex'));
    }
}

class SimpleRSAChunkEncryptor {
    constructor(publicKey, privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.chunkSize = 128; // Default chunk size for RSA-1024
    }

    powermod(base, exponent, modulus) {
        // Compute (base^exponent) % modulus efficiently using square and multiply algorithm
        if (modulus === 1n) return 0n;
        
        let result = 1n;
        base = base % modulus;
        
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1n;
            base = (base * base) % modulus;
        }
        
        return result;
    }

    encryptString(plaintext, compress = false) {
        // Step 1: Encode the plaintext to a Buffer
        let data;
        if (compress) {
            // Compress the data using pako
            data = pako.deflate(plaintext);
        } else {
            // Convert to UTF-8 encoded Buffer
            data = new TextEncoder().encode(plaintext);
        }
        
        const chunkSize = this.chunkSize - 1; // for making it starts without 0 !
    
        // Step 2: Split the data into chunks of the specified size
        const chunks = Array.from(
            { length: Math.ceil(data.length / chunkSize) },
            (_, i) => data.subarray(i * chunkSize, (i + 1) * chunkSize)
        );
    
        // Step 3: Encrypt each chunk using a series of transformation steps        
        const [e, n] = this.publicKey;
        const encryptedChunks = chunks
            // a. Convert chunk to hex
            .map(chunk => Buffer.from(chunk).toString('hex'))
            // b. Convert hex string to BigInt, make it starts without 0 !
            .map(chunkHex => BigInt('0x1' + chunkHex))
            // c. Encrypt the BigInt using the public key
            .map(chunkInt => this.powermod(chunkInt, e, n))
            // d. Convert the encrypted BigInt to a padded hex string
            .map(encryptedInt => encryptedInt.toString(16).padStart(this.chunkSize * 2, '0'))
            // e. Encode the hex string to Base64
            .map(encryptedHex => Buffer.from(encryptedHex, 'hex').toString('base64'));
    
        // Step 4: Join all the encrypted Base64-encoded chunks with a separator
        return encryptedChunks.join('|');
    }

    decryptString(encryptedData) {
        if (!this.privateKey) {
            throw new Error('Private key required for decryption.');
        }    
        const [d, n] = this.privateKey; // Destructure private key components once
    
        const encryptedChunks = encryptedData.split('|');
    
        // Step 1: Decode Base64 chunks to Buffers
        const decryptedChunks = encryptedChunks
                .map(chunk => Buffer.from(chunk, 'base64'))
                // Step 2: Convert Buffers to hex strings
                .map(buffer => buffer.toString('hex'))
                // Step 3: Convert hex strings to BigInts
                .map(hex => BigInt('0x' + hex))
                // Step 4: Decrypt BigInts using the private key
                .map(chunkInt => this.powermod(chunkInt, d, n))
                // Step 5: Convert decrypted BigInts to hex strings
                .map(chunkInt => chunkInt.toString(16))            
                // Step 6: Verify and slice hex strings, then convert to Buffers
                .map(hex => (hex[0] === '1' ? hex.slice(1) : 
                        (() => { throw new Error('decryptChunkHex must start with 0x1!'); })()))
                .map(slicedHex => Buffer.from(slicedHex, 'hex'));
    
        // Step 7: Concatenate Buffers
        const data = Buffer.concat(decryptedChunks);
    
        // Step 8: Decode the concatenated data
        const plainDecoder = new TextDecoder('utf-8', { fatal: true });
        try {
            return plainDecoder.decode(data); // Try decoding as UTF-8
        } catch {
            try {
                return pako.inflate(Uint8Array.from(data), { to: 'string' });
            } catch {
                throw new Error('Failed to decode data after all attempts.');
            }
        }
    }    
}

/**
 * Encrypts a JavaScript object to an encrypted JSON string using RSA encryption.
 * @param dataDict The JavaScript object to encrypt
 * @param publicPkcs8KeyPath Path to the public key file
 * @returns Encrypted string representation of the JSON data
 */
function dumpRJSONs(dataDict, publicPkcs8KeyPath) {
    const encryptor = new SimpleRSAChunkEncryptor(
        new PEMFileReader(publicPkcs8KeyPath).loadPublicPkcs8Key()
    );
    return encryptor.encryptString(JSON.stringify(dataDict));
}

/**
 * Decrypts an encrypted JSON string to a JavaScript object using RSA decryption.
 * @param encryptedData The encrypted JSON string
 * @param privatePkcs8KeyPath Path to the private key file
 * @returns Decrypted JavaScript object
 */
function loadRJSONs(encryptedData, privatePkcs8KeyPath) {
    const encryptor = new SimpleRSAChunkEncryptor(
        undefined,
        new PEMFileReader(privatePkcs8KeyPath).loadPrivatePkcs8Key()
    );
    return JSON.parse(encryptor.decryptString(encryptedData));
}

/**
 * Encrypts a JavaScript object and writes it to a file using RSA encryption.
 * @param dataDict The JavaScript object to encrypt
 * @param path Path where the encrypted data will be written
 * @param publicPkcs8KeyPath Path to the public key file
 * @returns void
 */
function dumpRJSON(dataDict, path, publicPkcs8KeyPath) {
    fs.writeFileSync(path, dumpRJSONs(dataDict, publicPkcs8KeyPath));
}

/**
 * Reads an encrypted JSON file and decrypts it to a JavaScript object using RSA decryption.
 * @param path Path to the encrypted JSON file
 * @param privatePkcs8KeyPath Path to the private key file
 * @returns Decrypted JavaScript object
 */
function loadRJSON(path, privatePkcs8KeyPath) {
    return loadRJSONs(fs.readFileSync(path, 'utf-8'), privatePkcs8KeyPath);
}

// Export functions for use in other modules
module.exports = {
    PEMFileReader,
    SimpleRSAChunkEncryptor,
    dumpRJSONs,
    loadRJSONs,
    dumpRJSON,
    loadRJSON,
};