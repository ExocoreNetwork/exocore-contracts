const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const axios = require('axios');
const ethers = require('ethers');
const wif = require('wif')
require("dotenv").config();

// Initialize ECPair and bitcoinjs-lib with the ecc library
const ECPair = ECPairFactory(ecc);

async function createStakingTransaction() {
    // Load environment variables
    const privateKey = process.env.TEST_ACCOUNT_THREE_PRIVATE_KEY;
    const vaultAddress = process.env.BTC_VAULT_ADDRESS;
    const depositAmount = 0.0001; // BTC, adjust as needed

    if (!privateKey || !vaultAddress) {
        throw new Error('Required environment variables are not set');
    }

    try {
        // Derive EVM address from private key
        const wallet = new ethers.Wallet(privateKey);
        const evmAddress = wallet.address.slice(2); // Remove '0x' prefix
        console.log('EVM address:', '0x' + evmAddress);

        // Create Bitcoin key pair
        const privateKeyBuffer = Buffer.from(privateKey.replace('0x', ''), 'hex');
        const keyPair = ECPair.fromPrivateKey(privateKeyBuffer, { 
            network: bitcoin.networks.testnet,
            compressed: true
        });

        // Create payment object once
        const payment = bitcoin.payments.p2wpkh({
            pubkey: keyPair.publicKey,  // Now this should work with proper ECC lib
            network: bitcoin.networks.testnet
        });

        // Get source address (we'll use SegWit for lower fees)
        const sourceAddress = payment.address;

        console.log('Bitcoin source address:', sourceAddress);

        // Fetch UTXOs using a testnet API
        const response = await axios.get(`https://blockstream.info/testnet/api/address/${sourceAddress}/utxo`);
        const utxos = response.data;

        if (utxos.length === 0) {
            throw new Error('No UTXOs found');
        }

        // Create transaction
        const psbt = new bitcoin.Psbt({ network: bitcoin.networks.testnet });

        // Add inputs
        let totalInput = 0;
        for (const utxo of utxos) {
            psbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: payment.output,
                    value: utxo.value
                }
            });
            
            totalInput += utxo.value;
            if (totalInput >= depositAmount * 100000000) break;
        }

        if (totalInput < depositAmount * 100000000) {
            throw new Error('Insufficient funds');
        }

        // Add OP_RETURN output with EVM address
        const opReturnScript = bitcoin.script.compile([
            bitcoin.opcodes.OP_RETURN,
            Buffer.from(evmAddress, 'hex')  // Direct hex encoding of EVM address (without 0x)
        ]);

        psbt.addOutput({
            script: opReturnScript,
            value: 0
        });

        // Add vault address output
        psbt.addOutput({
            address: vaultAddress,
            value: Math.floor(depositAmount * 100000000) // Convert BTC to satoshis
        });

        // Add change output if needed
        const fee = 1000; // 1000 satoshis fee
        const change = totalInput - (depositAmount * 100000000) - fee;
        if (change > 546) { // dust threshold
            psbt.addOutput({
                address: sourceAddress,
                value: change
            });
        }

        // Sign all inputs
        psbt.signAllInputs(keyPair);
        psbt.finalizeAllInputs();

        // Get transaction hex
        const tx = psbt.extractTransaction();
        console.log('Transaction hex:', tx.toHex());

        // Broadcast transaction
        const broadcastResponse = await axios.post(
            'https://blockstream.info/testnet/api/tx',
            tx.toHex(),
            { headers: { 'Content-Type': 'text/plain' } }
        );

        console.log('Transaction broadcasted:', broadcastResponse.data);
        return broadcastResponse.data; // txid
    } catch (error) {
        console.error('Error:', error.message);
        throw error;
    }
}

describe("Bitcoin Staking E2E Test", function() {
    it("should create and broadcast a staking transaction", async function() {
        const txid = await createStakingTransaction();
        console.log('Staking transaction successful. TXID:', txid);
    });
});