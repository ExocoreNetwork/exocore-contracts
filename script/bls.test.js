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

    const agg_pubkeys_tx = await blsCaller.aggregatePubkeys(pubkeys);
    // var gas = await provider.estimateGas({
    //     from: signer.address,
    //     to: blsCaller.target,
    //     data: blsCaller.interface.encodeFunctionData(
    //         "aggregatePubkeys", 
    //         [
    //             pubkeys
    //         ]
    //     ),
    //     function(estimatedGas, err) {
    //         console.log("estimatedGas: " + estimatedGas);
    //         console.log("Err:" + err);
    //     }
    // });
    // console.log("Gas: " + gas);
    await new Promise(resolve => setTimeout(resolve, 5000));

    const agg_pubkeys_tx_receipt = await provider.getTransactionReceipt(agg_pubkeys_tx.hash);
    // console.log("aggregate pubkeys tx receipt", agg_pubkeys_tx_receipt);
    console.log("aggregate pubkeys tx used gas:", agg_pubkeys_tx_receipt.gasUsed);

    var pubkey = await blsCaller.aggregatedPubkeys();
    console.log("aggregated pubkey", pubkey);
    var privkey = await blsCaller.generatePrivateKey();
    console.log("private key", privkey);

    await blsCaller.aggregateSigs(sigs);
    await new Promise(resolve => setTimeout(resolve, 3000));
    var sig = await blsCaller.aggregatedSigs();
    console.log("aggregated signature", sig);

    await blsCaller.verify(hashedMessage, sig, pubkey);
    await new Promise(resolve => setTimeout(resolve, 3000));
    var valid_1 = await blsCaller.verifyValid();
    console.log("verify result:", valid_1);

    const verify_tx = await blsCaller.fastAggregateVerify(hashedMessage, sig, pubkeys);
    await new Promise(resolve => setTimeout(resolve, 5000));

    const verify_tx_receipt = await provider.getTransactionReceipt(verify_tx.hash);
    // console.log("aggregate pubkeys tx receipt", agg_pubkeys_tx_receipt);
    console.log("aggregate verify tx used gas:", verify_tx_receipt.gasUsed);

    var valid_2 = await blsCaller.aggregateVerifyValid();
    console.log("verify result:", valid_2);

    const naiveCallerTemplate = await ethers.getContractFactory("BLS12381Caller2");
    const naiveCaller = await naiveCallerTemplate.connect(signer).deploy();
    await naiveCaller.waitForDeployment();
    console.log("BLS naive caller contract address", naiveCaller.target);

    const agg_pubkeys_tx_naive = await naiveCaller.aggregatePubkeys(pubkeys);
    await new Promise(resolve => setTimeout(resolve, 5000));

    const agg_pubkeys_tx_naive_receipt = await provider.getTransactionReceipt(agg_pubkeys_tx_naive.hash);
    // console.log("aggregate pubkeys tx receipt", agg_pubkeys_tx_receipt);
    console.log("naive aggregate pubkeys tx used gas:", agg_pubkeys_tx_naive_receipt.gasUsed);

    const pubkey_naive = await naiveCaller.aggregatedPubkeys();
    console.log("naive aggregated pubkey", pubkey_naive);

    const verify_tx_naive = await naiveCaller.fastAggregateVerify(hashedMessage, sig, pubkeys);
    await new Promise(resolve => setTimeout(resolve, 5000));

    const verify_tx_receipt_naive = await provider.getTransactionReceipt(verify_tx_naive.hash);
    // console.log("aggregate pubkeys tx receipt", agg_pubkeys_tx_receipt);
    console.log("naive aggregate verify tx used gas:", verify_tx_receipt_naive.gasUsed);

    var valid_naive = await naiveCaller.aggregateVerifyValid();
    console.log("verify result:", valid_naive);
    
    var totalExecuteTime = 0;
    var minExecuteTime = 0;
    var maxExecuteTime = 0;
    var currentExecuteTime;
    for (let i =0; i < 100; i++) {
        var startTime = performance.now();
        const agg_pure_result = await blsCaller.aggregatePubkeysPure(pubkeys);
        var endTime = performance.now();
        currentExecuteTime = endTime - startTime;
        totalExecuteTime += currentExecuteTime;
        if (currentExecuteTime > maxExecuteTime) {
            maxExecuteTime = currentExecuteTime;
        }
        if (currentExecuteTime < minExecuteTime || minExecuteTime == 0) {
            minExecuteTime = currentExecuteTime
        }
    }
    console.log(`Call to aggregate public keys took average ${totalExecuteTime/100} milliseconds, min ${minExecuteTime}, max ${maxExecuteTime}`);

    totalExecuteTime = 0;
    minExecuteTime = 0;
    maxExecuteTime = 0;
    for (let i =0; i < 100; i++) {
        var startTime = performance.now();
        const agg_pure_result = await naiveCaller.aggregatePubkeysPure(pubkeys);
        var endTime = performance.now();
        currentExecuteTime = endTime - startTime;
        totalExecuteTime += currentExecuteTime;
        if (currentExecuteTime > maxExecuteTime) {
            maxExecuteTime = currentExecuteTime;
        }
        if (currentExecuteTime < minExecuteTime || minExecuteTime == 0) {
            minExecuteTime = currentExecuteTime
        }
    }
    console.log(`Call to naive aggregate public keys took average ${totalExecuteTime/100} milliseconds, min ${minExecuteTime}, max ${maxExecuteTime}`);

    totalExecuteTime = 0;
    minExecuteTime = 0;
    maxExecuteTime = 0;
    for (let i =0; i < 100; i++) {
        var startTime = performance.now();
        const agg_pure_result = await blsCaller.fastAggregateVerifyPure(hashedMessage, sig, pubkeys);
        var endTime = performance.now();
        currentExecuteTime = endTime - startTime;
        totalExecuteTime += currentExecuteTime;
        if (currentExecuteTime > maxExecuteTime) {
            maxExecuteTime = currentExecuteTime;
        }
        if (currentExecuteTime < minExecuteTime || minExecuteTime == 0) {
            minExecuteTime = currentExecuteTime
        }
    }
    console.log(`Call to verify took average ${totalExecuteTime/100} milliseconds, min ${minExecuteTime}, max ${maxExecuteTime}`);

    totalExecuteTime = 0;
    minExecuteTime = 0;
    maxExecuteTime = 0;
    for (let i =0; i < 100; i++) {
        var startTime = performance.now();
        const agg_pure_result = await naiveCaller.fastAggregateVerifyPure(hashedMessage, sig, pubkeys);
        var endTime = performance.now();
        currentExecuteTime = endTime - startTime;
        totalExecuteTime += currentExecuteTime;
        if (currentExecuteTime > maxExecuteTime) {
            maxExecuteTime = currentExecuteTime;
        }
        if (currentExecuteTime < minExecuteTime || minExecuteTime == 0) {
            minExecuteTime = currentExecuteTime
        }
    }
    console.log(`Call to naive verify took average ${totalExecuteTime/100} milliseconds, min ${minExecuteTime}, max ${maxExecuteTime}`);
})();

