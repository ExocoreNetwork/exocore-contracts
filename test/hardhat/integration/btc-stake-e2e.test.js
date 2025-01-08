const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const axios = require('axios');
const { expect } = require("chai");
const fs = require('fs');
const path = require('path');
require("dotenv").config();

const ECPair = ECPairFactory(ecc);

const ASSETS_PRECOMPILE_ADDRESS = "0x0000000000000000000000000000000000000804";
const VIRTUAL_BTC_ADDR = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB";
const BTC_ID = ethers.getBytes(VIRTUAL_BTC_ADDR);

const BITCOIN_FAUCET_PRIVATE_KEY = process.env.TEST_ACCOUNT_THREE_PRIVATE_KEY;
const BITCOIN_ESPLORA_API_URL = process.env.BITCOIN_ESPLORA_API_URL;
const BITCOIN_VAULT_ADDRESS = process.env.BITCOIN_VAULT_ADDRESS;

if (!BITCOIN_ESPLORA_API_URL || !BITCOIN_FAUCET_PRIVATE_KEY || !BITCOIN_VAULT_ADDRESS) {
    throw new Error('BITCOIN_ESPLORA_API_URL or TEST_ACCOUNT_THREE_PRIVATE_KEY or BITCOIN_VAULT_ADDRESS is not set');
}

async function waitForBitcoinConfirmation(txid, confirmations = 1) {
    while (true) {
        try {
            const response = await axios.get(`${BITCOIN_ESPLORA_API_URL}/api/tx/${txid}`);
            if (response.data.confirmations >= confirmations) {
                return response.data;
            }
        } catch (error) {
            console.log('Waiting for transaction confirmation...');
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

async function fundBitcoinAddress(recipientAddress, amount) {
    if (!recipientAddress) {
        throw new Error('Recipient address is not set');
    }

    // Create Bitcoin key pairs
    const faucetKeyPair = ECPair.fromPrivateKey(
        Buffer.from(BITCOIN_FAUCET_PRIVATE_KEY.replace('0x', ''), 'hex'),
        { network: bitcoin.networks.regtest, compressed: true }
    );

    // Create payment objects
    const faucetPayment = bitcoin.payments.p2wpkh({
        pubkey: faucetKeyPair.publicKey,
        network: bitcoin.networks.regtest
    });

    console.log('Funding from address:', faucetPayment.address);
    console.log('Funding to address:', recipientAddress);

    try {
        // Fetch UTXOs from faucet
        const response = await axios.get(`${BITCOIN_ESPLORA_API_URL}/api/address/${faucetPayment.address}/utxo`);
        const utxos = response.data;

        if (utxos.length === 0) {
            throw new Error('No UTXOs found in faucet');
        }

        // Create funding transaction
        const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });

        // Add inputs
        let totalInput = 0;
        for (const utxo of utxos) {
            psbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: faucetPayment.output,
                    value: utxo.value
                }
            });
            
            totalInput += utxo.value;
            if (totalInput >= amount * 100000000) break;
        }

        if (totalInput < amount * 100000000) {
            throw new Error('Insufficient funds in faucet');
        }

        // Add recipient output
        psbt.addOutput({
            address: recipientAddress,
            value: Math.floor(amount * 100000000)
        });

        // Add change output
        const fee = 1000;
        const change = totalInput - (amount * 100000000) - fee;
        if (change > 546) {
            psbt.addOutput({
                address: faucetPayment.address,
                value: change
            });
        }

        // Sign and finalize
        psbt.signAllInputs(faucetKeyPair);
        psbt.finalizeAllInputs();

        // Broadcast transaction
        const tx = psbt.extractTransaction();
        const broadcastResponse = await axios.post(
            `${BITCOIN_ESPLORA_API_URL}/api/tx`,
            tx.toHex(),
            { headers: { 'Content-Type': 'text/plain' } }
        );

        console.log('Funding transaction broadcasted:', broadcastResponse.data);
        
        // Wait for confirmation
        await waitForBitcoinConfirmation(broadcastResponse.data);
        console.log('Funding transaction confirmed');

        return broadcastResponse.data;
    } catch (error) {
        console.error('Funding error:', error.message);
        throw error;
    }
}

async function createStakingTransaction(stakerPrivateKey, vaultAddress, depositAmount) {
    if (!stakerPrivateKey || !vaultAddress) {
        throw new Error('Required parameters are not set');
    }

    try {
        // Create Bitcoin key pair from private key
        const privateKeyBuffer = Buffer.from(stakerPrivateKey.replace('0x', ''), 'hex');
        const keyPair = ECPair.fromPrivateKey(privateKeyBuffer, { 
            network: bitcoin.networks.regtest,
            compressed: true
        });

        // Create payment object for source address
        const payment = bitcoin.payments.p2wpkh({
            pubkey: keyPair.publicKey,
            network: bitcoin.networks.regtest
        });

        // Get source address
        const sourceAddress = payment.address;
        console.log('Bitcoin source address:', sourceAddress);

        // Derive EVM address from same private key
        const wallet = new ethers.Wallet(stakerPrivateKey);
        const evmAddress = wallet.address.slice(2); // Remove '0x' prefix
        console.log('EVM address:', '0x' + evmAddress);

        // Fetch UTXOs
        const response = await axios.get(`${BITCOIN_ESPLORA_API_URL}/api/address/${sourceAddress}/utxo`);
        const utxos = response.data;

        if (utxos.length === 0) {
            throw new Error('No UTXOs found');
        }

        // Create transaction
        const psbt = new bitcoin.Psbt({ network: bitcoin.networks.regtest });

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
            Buffer.from(evmAddress, 'hex')
        ]);

        psbt.addOutput({
            script: opReturnScript,
            value: 0
        });

        // Add vault address output
        psbt.addOutput({
            address: vaultAddress,
            value: Math.floor(depositAmount * 100000000)
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
            `${BITCOIN_ESPLORA_API_URL}/api/tx`,
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
    let utxoGateway;
    let assetsPrecompile;
    let staker;
    let vault;

    const depositAmount = 0.01; // BTC
    const CLIENT_CHAIN = {
        NONE: 0,
        BTC: 1,
    };

    before(async function() {
        // Load deployed contracts
        const deployedContracts = JSON.parse(
            fs.readFileSync(
                path.join(__dirname, '../../../script/deployments/deployedContracts.json'),
                'utf8'
            )
        );

        // Get signers
        signers = await ethers.getSigners();
        staker = signers[signers.length - 2];
        vault = signers[signers.length - 1];
        console.log('Staker address:', staker.address);
        console.log('Vault address:', vault.address);

        // Initialize contracts from deployed addresses
        utxoGateway = await ethers.getContractAt(
            "UTXOGateway",
            deployedContracts.UTXOGateway.proxy
        );
        assetsPrecompile = await ethers.getContractAt(
            "IAssets",
            ASSETS_PRECOMPILE_ADDRESS
        );

        // Verify UTXOGateway is properly set up
        const [success, authorized] = await assetsPrecompile.isAuthorizedGateway(utxoGateway.target);
        expect(success).to.be.true;
        expect(authorized).to.be.true;

        // Verify BTC staking is activated
        const [chainSuccess, chainInfo] = await assetsPrecompile.getClientChainInfo(CLIENT_CHAIN.BTC);
        expect(chainSuccess).to.be.true;
        expect(chainInfo.isRegistered).to.be.true;

        // Fund staker's Bitcoin address with test BTC
        console.log('Funding staker address with test BTC...');
        const fundingAmount = 0.1; // Fund with more than needed for the test
        await fundBitcoinAddress(await staker.privateKey, fundingAmount);
        console.log('Staker address funded successfully');
    });

    it("should complete the full staking flow", async function() {
        // Get initial balance
        const [success, initialBalance] = await assetsPrecompile.getStakerBalanceByToken(
            CLIENT_CHAIN.BTC,
            ethers.getBytes(staker.address),
            BTC_ID
        );

        // Create and broadcast the Bitcoin transaction
        const txid = await createStakingTransaction(
            staker.privateKey,
            BITCOIN_VAULT_ADDRESS,
            depositAmount
        );
        console.log('Staking transaction broadcasted. TXID:', txid);

        // Wait for Bitcoin confirmation
        console.log('Waiting for Bitcoin confirmation...');
        const confirmedTx = await waitForBitcoinConfirmation(txid);
        console.log('Transaction confirmed with', confirmedTx.confirmations, 'confirmations');

        // Wait for DepositCompleted event
        console.log('Waiting for DepositCompleted event...');
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Timeout waiting for DepositCompleted event'));
            }, 60000);

            utxoGateway.on('DepositCompleted', async (
                clientChainId,
                txTag,
                depositorExoAddr,
                depositorClientChainAddr,
                amount,
                updatedBalance
            ) => {
                try {
                    if (depositorExoAddr.toLowerCase() === staker.address.toLowerCase()) {
                        clearTimeout(timeout);

                        // Verify final balance
                        const [finalSuccess, finalBalance] = await assetsPrecompile.getStakerBalanceByToken(
                            CLIENT_CHAIN.BTC,
                            ethers.getBytes(staker.address),
                            BTC_ID
                        );
                        
                        expect(finalSuccess).to.be.true;
                        const expectedIncrease = ethers.parseUnits('0.01', 8); // 0.01 BTC in satoshis
                        
                        // Check balance components
                        expect(finalBalance[0]).to.equal(CLIENT_CHAIN.BTC);  // clientChainID
                        expect(ethers.hexlify(finalBalance[1])).to.equal(ethers.hexlify(staker.address));  // stakerAddress
                        expect(ethers.hexlify(finalBalance[2])).to.equal(ethers.hexlify(BTC_ID));  // tokenId
                        expect(finalBalance[3]).to.equal(expectedIncrease);  // balance
                        expect(finalBalance[7]).to.equal(expectedIncrease);  // totalDeposited

                        console.log('Deposit completed successfully');
                        console.log('Initial balance:', initialBalance ? initialBalance[3] : 0);
                        console.log('Final balance:', finalBalance[3].toString());
                        
                        resolve();
                    }
                } catch (error) {
                    clearTimeout(timeout);
                    reject(error);
                }
            });
        });
    }).timeout(120000);
});