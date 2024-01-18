const { ethers, JsonRpcProvider } = require("ethers");

const provider = new JsonRpcProvider("http://127.0.0.1:8545");

var signer = new ethers.Wallet("0x8DD855BC33B90120375F7505044EDF5D197C8561630E262D27CBB98DBC4DAF76", provider);
var bls_raw_data = ""

provider.getBlockNumber().then(console.log);
console.log(signer.address);

(async () => {
    var deposit_tx = await signer.sendTransaction({
        to: "0x0000000000000000000000000000000000000804",
        value: 0,
        data: deposit_raw_data
    });
    console.log("deposit tx: ", deposit_tx);
    await new Promise(resolve => setTimeout(resolve, 5000));
    var deposit_tx_receipt = await provider.getTransactionReceipt(deposit_tx.hash);
    console.log("deposit tx receipt:", deposit_tx_receipt);

    var withdraw_tx = await signer.sendTransaction({
        to: "0x0000000000000000000000000000000000000808",
        value: 0,
        data: withdraw_raw_data
    });
    console.log("withdraw tx:", withdraw_tx);
    await new Promise(resolve => setTimeout(resolve, 5000));
    var withdraw_tx_receipt = await provider.getTransactionReceipt(withdraw_tx.hash);
    console.log("withdraw tx receipt:", withdraw_tx_receipt);
})();

