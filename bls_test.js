const fs = require('fs');
const ethers = require('ethers');

async function readKeysFromFile() {
  try {
    // Read the JSON file
    const jsonData = fs.readFileSync('bls_keys.json', 'utf-8');

    // Parse JSON data
    const keyPairs = JSON.parse(jsonData);

    // Iterate over key pairs
    for (const keyPair of keyPairs) {
      // Convert hex strings to Buffer
      const privateKeyBytes = Buffer.from(keyPair.private_key, 'hex');
      const publicKeyBytes = Buffer.from(keyPair.public_key, 'hex');
      const signatureBytes = Buffer.from(keyPair.signature, 'hex');

      // Print the bytes
      console.log(`Private Key Bytes: ${privateKeyBytes.toString('hex')}`);
      console.log(`Public Key Bytes: ${publicKeyBytes.toString('hex')}`);
      console.log(`Signature Bytes: ${signatureBytes.toString('hex')}`);
    }
  } catch (error) {
    console.error('Error reading keys from file:', error);
  }
}

readKeysFromFile();
