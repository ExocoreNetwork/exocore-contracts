require("dotenv").config();

const fs = require('fs');
const { ethers } = require("hardhat");

const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");

var signer = new ethers.Wallet(process.env.TEST_ACCOUNT_ONE_PRIVATE_KEY, provider);
var genesis_account = new ethers.Wallet(process.env.LOCAL_EXOCORE_VALIDATOR_SET_PRIVATE_KEY, provider);
const testMessage = 'this is a test message';

// Convert the message to bytes and hash it with keccak256
const hashedMessage = ethers.keccak256(ethers.toUtf8Bytes(testMessage));

var privkeys = [];
var pubkeys = [];
var sigs = [];

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

      privkeys.push(privateKeyBytes);
      pubkeys.push(publicKeyBytes);
      sigs.push(signatureBytes);

      // Print the bytes
    //   console.log(`Private Key Bytes: ${privateKeyBytes.toString('hex')}`);
    //   console.log(`Public Key Bytes: ${publicKeyBytes.toString('hex')}, length: ${publicKeyBytes.byteLength}`);
    //   console.log(`Signature Bytes: ${signatureBytes.toString('hex')}`);
    }
  } catch (error) {
    console.error('Error reading keys from file:', error);
  }
}

provider.getBlockNumber().then(console.log);
console.log(signer.address);

(async () => {
    await readKeysFromFile();

    var balance = await provider.getBalance(process.env.TEST_ACCOUNT_ONE_ADDRESS);
    if (balance < 1e18) {
        var transfer_tx = await genesis_account.sendTransaction({
            to: process.env.TEST_ACCOUNT_ONE_ADDRESS,
            value: ethers.parseEther('100.0'),
            data: "0x"
        });
        console.log("transfer tx: ", transfer_tx);
        await new Promise(resolve => setTimeout(resolve, 5000));
        // var transfer_tx_receipt = await provider.getTransactionReceipt(transfer_tx.hash);
        // console.log("transfer tx receipt:", transfer_tx_receipt);
        
        console.log("test account one balance:", ethers.formatEther(balance));
    }

    const blsCallerTemplate = await ethers.getContractFactory("BLS12381Caller");
    const blsCaller = await blsCallerTemplate.connect(signer).deploy();
    await blsCaller.waitForDeployment();
    console.log("BLS caller contract address", blsCaller.target);

    const naiveCallerTemplate = await ethers.getContractFactory("BLS12381Caller2");
    const naiveCaller = await naiveCallerTemplate.connect(signer).deploy();
    await naiveCaller.waitForDeployment();
    console.log("BLS naive caller contract address", naiveCaller.target);

    await blsCaller.aggregateSigs(sigs);
    await new Promise(resolve => setTimeout(resolve, 3000));
    var sig = await blsCaller.aggregatedSigs();
    console.log("aggregated signature", sig);
    
    for (let i = 0; i < 10; i++) {
        const agg_pure_result = await blsCaller.aggregatePubkeysPure(pubkeys);
        console.log("agg pub key:", agg_pure_result);

        const naive_agg_pure_result = await naiveCaller.aggregatePubkeysPure(pubkeys);
        console.log("naive agg pub key:", naive_agg_pure_result);

        const verify_result = await blsCaller.fastAggregateVerifyPure(hashedMessage, sig, pubkeys);
        console.log("verify result:", verify_result);

        const naive_verify_result = await naiveCaller.fastAggregateVerifyPure(hashedMessage, sig, pubkeys);
        console.log("naive verify result:", naive_verify_result)
    }
})();

