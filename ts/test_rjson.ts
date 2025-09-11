import { PEMFileReader,SimpleRSAChunkEncryptor,dumpRJSON,loadRJSON } from './rjson';


function ex3() {
    const publicKeyPath = '../tmp/public_key.pem';
    const privateKeyPath = '../tmp/private_key.pem';

    // Load keys from .pem files
    const publicKey = new PEMFileReader(publicKeyPath).loadPublicPkcs8Key();
    const privateKey = new PEMFileReader(privateKeyPath).loadPrivatePkcs8Key();

    // Instantiate the encryptor with the loaded keys
    const encryptor = new SimpleRSAChunkEncryptor(publicKey, privateKey);

    // Encrypt and decrypt a sample string
    var plaintext = "Hello, RSA encryption with .pem support!";
    console.log(`Original Plaintext: [${plaintext}]`);

    // Encrypt the plaintext
    const encryptedText = encryptor.encryptString(plaintext, true);
    console.log(`\nEncrypted (Base64 encoded): [${encryptedText}]`);

    // Decrypt the encrypted text
    const decryptedText = encryptor.decryptString(encryptedText);
    console.log(`\nDecrypted Text: [${decryptedText}]`);
}

function ex4() {
    const publicKeyPath = '../tmp/public_key.pem';
    const privateKeyPath = '../tmp/private_key.pem';
    
    // Create a sample JavaScript object
    const data = {
        name: "John Doe",
        age: 30,
        email: "john.doe@example.com",
        roles: ["admin", "user"],
        metadata: {
            lastLogin: new Date().toISOString(),
            preferences: {
                theme: "dark",
                notifications: true
            }
        }
    };
    
    console.log("Original data:", data);
    
    // Encrypt and save to file
    const filePath = "../tmp/encrypted_data.rjson";
    dumpRJSON(data, filePath, publicKeyPath);
    console.log(`\nData encrypted and saved to ${filePath}`);
    
    // Load and decrypt from file
    const decryptedData = loadRJSON(filePath, privateKeyPath);
    console.log("\nDecrypted data:", decryptedData);
}

// npx tsx RSA.ts
ex3()
ex4()