require("dotenv").config();

const fs = require('fs');
const { ethers } = require("hardhat");

const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");

var signer = new ethers.Wallet(process.env.TEST_ACCOUNT_ONE_PRIVATE_KEY, provider);
var genesis_account = new ethers.Wallet(process.env.LOCAL_EXOCORE_VALIDATOR_SET_PRIVATE_KEY, provider);

var pubkeys = [];
var sigma;
var apkG2;
var msg;

async function readKeysFromFile() {
  try {
    // Read the JSON file
    const jsonFile = fs.readFileSync('script/bn254Pubkeys.json', 'utf-8');

    // Parse JSON data
    const jsonData = JSON.parse(jsonFile);

    apkG2 = {
        X: [
            BigInt(jsonData.apkG2[0]), 
            BigInt(jsonData.apkG2[1])
        ], 
        Y: [
            BigInt(jsonData.apkG2[2]), 
            BigInt(jsonData.apkG2[3])
        ]
    };
    // console.log("apkG2", apkG2)

    msg = Buffer.from(jsonData.msg, 'hex');
    // console.log("msg: ", msg)

    sigma = {
        X: BigInt(jsonData.sigma[0]), 
        Y: BigInt(jsonData.sigma[1])
    }
    // console.log("sigma: ", sigma)

    // Iterate over key pairs
    for (const key in jsonData.pubkeys) {
      var pubkey = {
        X: BigInt(jsonData.pubkeys[key][0]), 
        Y: BigInt(jsonData.pubkeys[key][1])
    };

      pubkeys.push(pubkey);

      console.log("pubkey:", pubkey)
    }
  } catch (error) {
    console.error('Error reading keys from file:', error);
  }
}

(async () => {
    await readKeysFromFile();

    var balance = await provider.getBalance(process.env.TEST_ACCOUNT_ONE_ADDRESS);
    if (balance < 1e18) {
        var transfer_tx = await genesis_account.sendTransaction({
            to: process.env.TEST_ACCOUNT_ONE_ADDRESS,
            value: ethers.parseEther('100.0'),
            data: "0x"
        });
        // console.log("transfer tx: ", transfer_tx);
        await new Promise(resolve => setTimeout(resolve, 5000));
        // var transfer_tx_receipt = await provider.getTransactionReceipt(transfer_tx.hash);
        // console.log("transfer tx receipt:", transfer_tx_receipt);
        console.log("test account one balance:", ethers.formatEther(balance));
    }

    const bn254CallerTemplate = await ethers.getContractFactory("BN254Caller");
    const bn254Caller = await bn254CallerTemplate.connect(signer).deploy();
    await bn254Caller.waitForDeployment();
    console.log("BN254 caller contract address", bn254Caller.target);

    var sli = [];
    sli[0] = {
        X: BigInt(13555814479934889599112388987672606386712509658558063457129754098335199913140), 
        Y: BigInt(16292187093937128991592377425107368795379599081914461646412822674855318863795)
    }
    sli[1] = {
        X: BigInt(19889110207503694262791024509487907356825893878939760687116967029883160557374), 
        Y: BigInt(1028511241727538358185561476133425746157478703257737457879413838777938441615)
    }
    var rawData = bn254Caller.interface.encodeFunctionData(
        "aggregatePubkeysPure",
        [
            sli
        ]
    );
    console.log("encoded data:", rawData);
    
    var ret = await provider.call({
        to: bn254Caller.target,
        data: rawData
    })
    console.log(ret)
    // for (let i = 0; i < 10; i++) {
    //     console.log("pubkeys:", pubkeys.slice(0,2));
    //     const apk = await bn254Caller.aggregatePubkeysPure(pubkeys.slice(0,2));
    //     console.log("apk:", apk);

    //     const valid = await bn254Caller.fastAggregateVerifyPure(msg, pubkeys, apkG2, sigma);
    //     console.log("valid:", valid)
    // }
})();

