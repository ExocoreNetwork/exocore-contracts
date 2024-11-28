// conventions are that the snake_case is within the JSON
// and variables within this file are title case

// global constants include the chain information
const clientChainInfo = {
  'name': 'Sepolia',
  'meta_info': 'Ethereum-testnet known as Sepolia',
  'finalization_blocks': 10,
  'layer_zero_chain_id': 40161,
  'address_length': 20,
};
// this must be in the same order as whitelistTokens
const tokenMetaInfos = [
  'Staked ETH',
  'Exocore testnet ETH',
  'Lido wrapped staked ETH',
];
// this must be in the same order as whitelistTokens
// they are provided because the symbol may not match what we are using from the price feeder.
// for example, exoETH is not a real token and we are using the price feed for ETH.
// the script will take care of mapping the nstETH asset_id to the ETH asset_id in the oracle
// tokens list.
const tokenNamesForOracle = [
  'nstETH', 'ETH', 'wstETH' // not case sensitive
]
const nativeChain = {
  "name": "Exocore",
  "meta_info": "The (native) Exocore chain",
  "finalization_blocks": 10,
  "layer_zero_chain_id": 0, // virtual chain
  "address_length": 20,
}
const nativeAsset = {
  "asset_basic_info": {
    "name": "Native EXO token",
    "symbol": "exo",
    "address": "0x0000000000000000000000000000000000000000",
    "decimals": "18",
    "layer_zero_chain_id": nativeChain.layer_zero_chain_id,
    "exocore_chain_index": "1",
    "meta_info": "EXO native to the Exocore chain",
  },
  "staking_total_amount": "0"
};
const EXOCORE_BECH32_PREFIX = 'exo';
const VIRTUAL_STAKED_ETH_ADDR = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

import dotenv from 'dotenv';
dotenv.config();
import { decode } from 'bech32';
import { promises as fs } from 'fs';
import Web3 from 'web3';
import Decimal from 'decimal.js';

import { getClient } from "@lodestar/api";
import { config } from "@lodestar/config/default";

const isValidBech32 = (address) => {
  try {
    const { prefix, words } = decode(address);
    if (!prefix || !words.length) {
      return false;
    }
    return prefix === EXOCORE_BECH32_PREFIX;
  } catch (error) {
    // If there's any error in decoding, return false
    return false;
  }
}


// Load variables from .env file
const { 
  INTEGRATION_BEACON_CHAIN_ENDPOINT,
  CLIENT_CHAIN_RPC,
  INTEGRATION_BOOTSTRAP_ADDRESS,
  INTEGRATION_BASE_GENESIS_FILE_PATH,
  INTEGRATION_RESULT_GENESIS_FILE_PATH,
  INTEGRATION_EXCHANGE_RATES
} = process.env;


if (
    !INTEGRATION_BEACON_CHAIN_ENDPOINT ||
    !CLIENT_CHAIN_RPC ||
    !INTEGRATION_BOOTSTRAP_ADDRESS ||
    !INTEGRATION_BASE_GENESIS_FILE_PATH ||
    !INTEGRATION_RESULT_GENESIS_FILE_PATH ||
    !INTEGRATION_EXCHANGE_RATES
) {
    throw new Error('One or more required environment variables are missing.');
}

import pkg from 'js-sha3';
const { keccak256 } = pkg;

import JSONbig from 'json-bigint';
const jsonBig = JSONbig({ useNativeBigInt: true });


function getChainIDWithoutPrevision(chainID) {
  const splitStr = chainID.split('-');
  return splitStr[0];
}

function generateAVSAddr(chainID) {
  const ChainIDPrefix = 'chain-id-prefix';
  const hash = keccak256(ChainIDPrefix + chainID);

  return '0x' + hash.slice(-40);
}

function getJoinedStoreKey(...keys) {
  const joinedString = keys.join('/');
  return joinedString;
}

async function updateGenesisFile() {
  try {
    // Read and parse the ABI from abi.json
    const abiPath = './out/Bootstrap.sol/Bootstrap.json';
    const contractABI = JSON.parse(await fs.readFile(abiPath, 'utf8')).abi;

    // Set up Web3
    const web3 = new Web3(CLIENT_CHAIN_RPC);

    // Create contract instance
    const myContract = new web3.eth.Contract(contractABI, INTEGRATION_BOOTSTRAP_ADDRESS);
    // Create beacon API client
    const api = getClient({baseUrl: INTEGRATION_BEACON_CHAIN_ENDPOINT}, {config});
    const spec = (await api.config.getSpec()).value();
    const maxEffectiveBalance = new Decimal(web3.utils.toWei(spec.MAX_EFFECTIVE_BALANCE, 'gwei'));
    const ejectionBalance = new Decimal(web3.utils.toWei(spec.EJECTION_BALANCE, 'gwei'));
    const slotsPerEpoch = parseInt(spec.SLOTS_PER_EPOCH, 10);
    let lastHeader = (await api.beacon.getBlockHeader({blockId: "finalized"})).value();
    const finalizedSlot = lastHeader.header.message.slot;
    const finalizedEpoch = Math.floor(finalizedSlot / slotsPerEpoch);
    if (finalizedSlot % slotsPerEpoch != 0) {
      // change the header
      lastHeader = (await api.beacon.getBlockHeader({blockId: finalizedEpoch * slotsPerEpoch})).value();
    }
    const stateRoot = web3.utils.bytesToHex(lastHeader.header.message.stateRoot);

    // Read exchange rates
    const exchangeRates = INTEGRATION_EXCHANGE_RATES.split(',').map(Decimal);

    // Read the genesis file
    const genesisData = await fs.readFile(INTEGRATION_BASE_GENESIS_FILE_PATH);
    const genesisJSON = jsonBig.parse(genesisData);

    // the initial height, when starting a new chain, is 1.
    // however, when restarting an exported chain, it is 1 + the last block in the
    // exported chain. to that end, we will set an initial_height of 0, if
    // the genesis file has it set as 1. this will allow the first block to be
    // free of any genesis state which depends on the height.
    let height = parseInt(genesisJSON.initial_height, 10);
    if (height == 1) {
      height = 0;
    }

    const bootstrapped = await myContract.methods.bootstrapped().call();
    if (bootstrapped) {
      throw new Error('The contract has already been bootstrapped.');
    }

    // Set spawn time
    const spawnTime = await myContract.methods.spawnTime().call();
    const spawnTimeInSeconds = spawnTime.toString();
    const spawnDate = new Date(spawnTimeInSeconds * 1000).toISOString();
    genesisJSON.genesis_time = spawnDate;

    // x/assets: client_chains (client_chain.go)
    if (!genesisJSON.app_state) {
      genesisJSON.app_state = {};
    }
    if (!genesisJSON.app_state.assets) {
      genesisJSON.app_state.assets = {};
    }
    if (!genesisJSON.app_state.assets.client_chains) {
      genesisJSON.app_state.assets.client_chains = [];
    }
    const existingChainIdIndex = genesisJSON.app_state.
      assets.client_chains.findIndex(
        chain =>
          chain.layer_zero_chain_id === clientChainInfo.layer_zero_chain_id
      );
    if (existingChainIdIndex >= 0) {
      // If found, raise an error
      throw new Error(
        `An entry with layer_zero_chain_id
        ${clientChainInfo.layer_zero_chain_id} already exists.`
      );
    }
    genesisJSON.app_state.assets.client_chains.push(clientChainInfo);
    genesisJSON.app_state.assets.client_chains.sort(
      (a, b) => a.layer_zero_chain_id - b.layer_zero_chain_id
    );

    const clientChainSuffix = '_0x' + clientChainInfo.layer_zero_chain_id.toString(16);

    // x/assets: tokens (client_chain_asset.go)
    // x/oracle
    if (!genesisJSON.app_state.assets.tokens) {
      genesisJSON.app_state.assets.tokens = [];
    }
    if (!genesisJSON.app_state.oracle.params.tokens) {
      throw new Error(
        'The tokens section is missing from the oracle params.'
      );
    } else if (genesisJSON.app_state.oracle.params.tokens.length > 1) {
      // remove the ETH default token
      genesisJSON.app_state.oracle.params.tokens = genesisJSON.app_state.oracle.params.tokens.slice(0, 1);
    }
    if (!genesisJSON.app_state.oracle.params.token_feeders) {
      throw new Error(
        'The token_feeders section is missing from the oracle params.'
      );
    } else if (genesisJSON.app_state.oracle.params.token_feeders.length > 1) {
      // remove the ETH default token
      genesisJSON.app_state.oracle.params.token_feeders = genesisJSON.app_state.oracle.params.token_feeders.slice(
        0, 1
      );
    }
    const supportedTokensCount = await myContract.methods.getWhitelistedTokensCount().call();
    if (supportedTokensCount != tokenMetaInfos.length) {
      throw new Error(
        `The number of tokens in the contract (${supportedTokensCount}) 
        does not match the number of token meta infos (${tokenMetaInfos.length}).`
      );
    }
    if (supportedTokensCount != tokenNamesForOracle.length) {
      throw new Error(
        `The number of tokens in the contract (${supportedTokensCount}) 
        does not match the number of token names for the oracle (${tokenNamesForOracle.length}).`
      );
    }
    const decimals = [];
    const supportedTokens = [];
    const assetIds = [];
    // start with the initial value
    const oracleTokens = genesisJSON.app_state.oracle.params.tokens;
    const oracleTokenFeeders = genesisJSON.app_state.oracle.params.token_feeders;
    let hasNst = {};
    for (let i = 0; i < supportedTokensCount; i++) {
      let token = await myContract.methods.getWhitelistedTokenAtIndex(i).call();
      const deposit_amount = await myContract.methods.depositsByToken(token.tokenAddress).call();
      const tokenCleaned = {
        asset_basic_info: {
          name: token.name,
          symbol: token.symbol,
          address: token.tokenAddress.toLowerCase(),
          decimals: token.decimals.toString(),
          layer_zero_chain_id: clientChainInfo.layer_zero_chain_id,
          exocore_chain_index: i.toString(), // unused
          meta_info: tokenMetaInfos[i],
        },
        staking_total_amount: deposit_amount.toString(),
      };

      supportedTokens[i] = tokenCleaned;
      decimals.push(token.decimals);
      assetIds.push(token.tokenAddress.toLowerCase() + clientChainSuffix);
      let oracleToken;
      const oracleTokenFeeder = {
        token_id: (i + 1).toString(), // first is reserved
        rule_id: "1",
        start_round_id: "1",
        start_base_block: (height + 20).toString(),
        interval: "30",
        end_block: "0",
      };
      if (tokenNamesForOracle[i].toLowerCase().startsWith('nst')) {
        if (token.tokenAddress != VIRTUAL_STAKED_ETH_ADDR) {
          throw new Error('Oracle name refers to NST token but this is LST');
        }
        oracleToken = {
          name: tokenNamesForOracle[i],
          chain_id: 1, // first chain in the list
          contract_address: '',
          active: true,
          asset_id: "NST" + clientChainSuffix,
          decimal: 0,
        };
      } else {
        if (token.tokenAddress == VIRTUAL_STAKED_ETH_ADDR) {
          throw new Error('Oracle name refers to LST token but this is NST');
        }
        oracleToken = {
          name: tokenNamesForOracle[i],
          chain_id: 1,
          contract_address: token.tokenAddress,
          active: true,
          asset_id: token.tokenAddress.toLowerCase() + clientChainSuffix,
          decimal: 8,
        };
      }
      oracleTokens.push(oracleToken);
      oracleTokenFeeders.push(oracleTokenFeeder);
      if (oracleToken.name.toLowerCase().startsWith('nst')) {
        if (hasNst.status) {
          throw new Error('Multiple NST tokens found.');
        }
        hasNst = {
          // only used for tracking multiple NST tokens
          status: true,
          asset_id: token.tokenAddress.toLowerCase() + clientChainSuffix,
          remainder: oracleToken.name.slice(3),
        };
      }
      // break;
    }
    // bind nstETH asset_id to the ETH token, if nstETH is found.
    let found = false;
    genesisJSON.app_state.oracle.params.tokens = oracleTokens.map((token) => {
      if (token.name == hasNst.remainder) {
        found = true;
        token.asset_id += "," + hasNst.asset_id;
      }
      return token;
    });
    if (!found && hasNst.status) {
      // add `ETH` manually, if `nstETH` exists but not `ETH` in the oracle tokens.
      // the former in `tokens` is to get the validator effective balance from beacon, denominated in ETH.
      // the latter in `tokens` is to get the price of ETH in USD.
      genesisJSON.app_state.oracle.params.tokens.push({
        name: hasNst.remainder,
        chain_id: 1,
        contract_address: VIRTUAL_STAKED_ETH_ADDR,
        active: true,
        asset_id: hasNst.asset_id,
        decimal: 8,
      });
      genesisJSON.app_state.oracle.params.token_feeders.push({
        token_id: (Number(supportedTokensCount) + 1).toString(),
        rule_id: "1",
        start_round_id: "1",
        start_base_block: (height + 20).toString(),
        interval: "30",
        end_block: "0",
      });
    }
    genesisJSON.app_state.oracle.params.token_feeders = oracleTokenFeeders;
    supportedTokens.sort((a, b) => {
      if (a.asset_basic_info.symbol < b.asset_basic_info.symbol) {
        return -1;
      }
      if (a.asset_basic_info.symbol > b.asset_basic_info.symbol) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.assets.tokens = supportedTokens;
    // do not sort x/oracle params since the order is related for
    // the token objects and the token feeders.

    // x/assets: deposits (staker_asset.go)
    if (!genesisJSON.app_state.assets.deposits) {
      genesisJSON.app_state.assets.deposits = [];
    }
    const depositorsCount = await myContract.methods.getDepositorsCount().call();
    const deposits = [];
    const nativeTokenDepositors = [];
    const staker_infos = [];
    let slashProportions = [];
    let staker_index_counter = 0;
    for (let i = 0; i < depositorsCount; i++) {
      const stakerAddress = await myContract.methods.depositors(i).call();
      const depositsByStaker = [];
      for (let j = 0; j < supportedTokensCount; j++) {
        // do not reuse the older array since it has been sorted.
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        let depositValue = new Decimal((await myContract.methods.totalDepositAmounts(
          stakerAddress, tokenAddress
        ).call()).toString());
        let withdrawableValue = new Decimal((await myContract.methods.withdrawableAmounts(
          stakerAddress, tokenAddress
        ).call()).toString());
        // for validator pubkey ids to be available, a deposit must have been made.
        // hence, the depositValue > 0 condition is necessary.
        if ((tokenAddress == VIRTUAL_STAKED_ETH_ADDR) && (depositValue > 0)) {
          // we have to use the effective balance calculation
          nativeTokenDepositors.push(stakerAddress.toLowerCase());
          const pubKeyCount = await myContract.methods.getPubkeysCount(stakerAddress).call();
          if (pubKeyCount == 0) {
            throw new Error('No pubkeys found for the staker.');
          }
          const pubKeys = [];
          for(let k = 0; k < pubKeyCount; k++) {
            pubKeys.push(await myContract.methods.stakerToPubkeyIDs(stakerAddress, k).call());
          }
          if (pubKeys.length == 0) {
            throw new Error('No pubkeys found for the staker.');
          }
          const staker_info = {
            staker_addr: stakerAddress.toLowerCase(),
            staker_index: staker_index_counter,
            validator_pubkey_list: pubKeys,
            balance_list: [] // filled later.
          };
          staker_index_counter += 1;
          const validatorStates = (await api.beacon.getStateValidators(
            {stateId: stateRoot, validatorIds: pubKeys.map(pubKey => parseInt(pubKey, 16))}
          )).value();
          let totalEffectiveBalance = new Decimal(0);
          let balances = [];
          // remember that these validators are specific to the provided staker address.
          // a validator is identified by its public key (or validator index), while a staker
          // is identified by its address. each staker may have multiple validators.
          for(let k = 0; k < validatorStates.length; k++) {
            // we cannot drop validators even though they may be slashed. this is because
            // even after slashing, the validators will retain 16 ETH of total balance.
            // this must be allowed to be withdrawn after Exocore is launched. since the
            // withdrawal credentials point to the ExoCapsule, such a withdrawal will
            // be permitted only via Exocore, which must, correspondingly, have this validator's
            // state recorded.
            const validator = validatorStates[k];
            const effectiveBalance = new Decimal(web3.utils.toWei(validator.validator.effectiveBalance.toString(), "gwei"));
            if (effectiveBalance.eq(0)) {
              if (!validator.status.startsWith("withdrawal")) {
                throw new Error(
                  `The effective balance of ${effectiveBalance} is zero for a validator that is not withdrawing.`
                );
              }
            }
            // even if max is 16, this will still hold
            if (effectiveBalance.gt(maxEffectiveBalance)) {
              throw new Error(
                `The effective balance of ${effectiveBalance} is greater than the maximum effective balance.`
              );
            }
            if (validator.status == "pending_initialized") {
              // the deposit has happened, but perhaps not enough, or churn limit is exceeded,
              // or the simplest case, the epoch containing the deposit has not yet ended.
              // ideally, the effective balance should be equal to the depositValue, which
              // would sum all the deposits made to the beacon chain.
              // however, if a proof for a deposit was not submitted to the Bootstrap contract,
              // but a deposit was made, the effective balance > depositValue.
              // in a live chain, either a proof submission is made, or, the price feeder
              // performs such an update. we will handle the update here ourselves.
              // here, if the epoch in which the deposit was made hasn't ended, the effective
              // balance may possibly be equal to 32 ETH. hence, we cannot check any range
              // for this case.
            } else if (validator.status == "pending_queued") {
              // the deposit has happened, but the validator is not yet active. in this case,
              // the effective balance must be exactly 32 ETH. otherwise, it would never be
              // activated.
              if (effectiveBalance.ne(maxEffectiveBalance)) {
                throw new Error(
                  `The effective balance of ${effectiveBalance} is not equal to the maximum effective balance.`
                );
              }
            } else if (validator.status.startsWith("active") || validator.status.startsWith("exited")) {
              if (validator.status.endsWith("slashed")) {
                // [8, 16]
                if (effectiveBalance.gt(ejectionBalance)) {
                  throw new Error(
                    `The effective balance of ${effectiveBalance} is greater than the ejection balance.`
                  );
                } else if (effectiveBalance.lt(ejectionBalance.div(2))) {
                  throw new Error(
                    `The effective balance of ${effectiveBalance} is less than half the ejection balance.`
                  );
                }
              } else {
                // [16, 32], of which 32 is already checked.
                if (effectiveBalance.lt(ejectionBalance)) {
                  throw new Error(
                    `The effective balance of ${effectiveBalance} is less than the ejection balance.`
                  );
                }
              }
            } else {
              // beacon chain withdrawal, may or may not have landed on the execution layer.
              // we will need to record this in state nevertheless, because withdrawal of the execution layer ETH
              // must be permitted.
              if (!effectiveBalance.isZero()) {
                throw new Error(
                  `The effective balance of ${effectiveBalance} is not zero for a withdrawal status.`
                );
              }
            }
            totalEffectiveBalance = totalEffectiveBalance.plus(effectiveBalance);
            let new_balance = {
              round_id: 0,
              block: height,
              index: 0,
              balance: 0,
              // since we are only considering the total amount after slashing and refunds,
              // it is always a deposit.
              change: "ACTION_DEPOSIT"
            };
            if (balances.length > 0) {
              new_balance = balances[balances.length - 1];
              new_balance.index += 1;
            }
            new_balance.balance = web3.utils.fromWei(effectiveBalance.toFixed(), "ether");
            balances.push(new_balance);
          }
          // now we have the totalEffectiveBalance across all validator pubkeys for this staker
          // we will compare it with the depositValue. ideally, they should be equal. however,
          // a deposit proof may not have been submitted or the validator might have been
          // slashed, causing a deviation. it is also possible for a validator to have exited
          // from the beacon chain (without attempting to submit a proof), causing a deviation.
          if (totalEffectiveBalance.eq(depositValue)) {
            // (1) they are equal; do nothing
          } else if (totalEffectiveBalance.lt(depositValue)) {
            // (2) totalEffectiveBalance > depositValue; add spare as deposit but not withdrawable
            depositValue = totalEffectiveBalance;
          } else {
            // (3) lower effective balance means that the Ethereum validator was either downtime
            // penalised or slashed. we follow the logic enshrined in update_native_restaking_balance.go
            // store this value before making any adjustments to calculate the slash proportion accurately.
            let totalDelegated = depositValue.minus(withdrawableValue);
            let slashFromWithdrawable = depositValue.minus(totalEffectiveBalance);
            let pendingSlashAmount = slashFromWithdrawable.minus(withdrawableValue);
            if (pendingSlashAmount.isPositive()) {
              slashFromWithdrawable = withdrawableValue;
            } else {
              pendingSlashAmount = new Decimal(0);
            }
            depositValue = depositValue.minus(slashFromWithdrawable);
            withdrawableValue = withdrawableValue.minus(slashFromWithdrawable);
            // we don't have any undelegations, so we will skip that step.
            if (pendingSlashAmount.isPositive()) {
              // slash across all delegations, propotionately.
              // let's look at an example.
              // effective balance = 16 ETH at the time of generate.mjs
              // originally, deposit value = 32 ETH, withdrawable value = 8 ETH
              // slash from withdrawable = 16 ETH
              // pending slash amount = 8 ETH
              // slash from withdrawable = 8 ETH
              // deposit value = 24 ETH, withdrawable value = 0 ETH
              // we still have to slash 8 ETH of total delegated 24 ETH, across all operators
              // to which delegations exist. so, 1/3 needs to be slashed. it should be saved
              // and applied to staker_asset and operator_asset etc.
              // in addition, we will apply it to the depositValue here too.
              // total delegated was originally 24 ETH. so, 8 ETH (=1/3) needs to be slashed.
              // the slashing needs to be applied to
              // -- staker + asset + {each validator to which that combination is delegated}
              // it should be applied to the delegated value against each validator,
              // and then it will flow automatically(?) to the share.
              let slashProportion = pendingSlashAmount.div(totalDelegated);
              if (slashProportion.greaterThan(new Decimal(1))) {
                slashProportion = new Decimal(1);
              }
              depositValue = totalDelegated.mul((new Decimal(1)).minus(slashProportion));
              // a certain subset of the validators is impacted by this above slashing.
              // our goal is to find that subset and save it such that it can be applied
              // to the delegated value below.
              let impactedValidators = [];
              let impactedValidatorsCount = 
                await myContract.methods.getValidatorsCountForStakerToken(stakerAddress, tokenAddress).call();
              for(let k = 0; k < impactedValidatorsCount; k++) {
                let impactedValidator = 
                  await myContract.methods.stakerToTokenToValidators(stakerAddress, tokenAddress, k).call();
                impactedValidators.push(impactedValidator);
              }
              if ((impactedValidators.length == 0) && (!slashProportion.isZero())) {
                slashProportions.push({
                  staker: stakerAddress,
                  token: tokenAddress,
                  proportion: slashProportion,
                  impacted_validators: impactedValidators
                });
              }
            }
          }
          staker_info.balance_list = balances;
          if (!totalEffectiveBalance.isZero()) {
            staker_infos.push(staker_info);
          }
        }
        const depositByStakerForAsset = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          info: {
            // adjusted for slashing by ETH beacon chain
            total_deposit_amount: depositValue.toFixed(),
            withdrawable_amount: withdrawableValue.toFixed(),
            pending_undelegation_amount: "0",
          }
        };
        depositsByStaker.push(depositByStakerForAsset);
        // break;
      }
      // sort for determinism
      depositsByStaker.sort((a, b) => {
        // the asset_id is guaranteed to be unique, so no further sorting is needed.
        if (a.asset_id < b.asset_id) {
          return -1;
        }
        if (a.asset_id > b.asset_id) {
          return 1;
        }
        return 0;
      });
      const depositsByStakerWrapped = {
        staker: stakerAddress.toLowerCase() + clientChainSuffix,
        deposits: depositsByStaker
      };
      deposits.push(depositsByStakerWrapped);
      // break;
    }
    // sort for determinism
    deposits.sort((a, b) => {
      // the staker_id is guaranteed to be unique, so no further sorting is needed.
      if (a.staker < b.staker) {
        return -1;
      }
      if (a.staker > b.staker) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.assets.deposits = deposits;

    // x/assets: assets state of the operators
    const validatorCount = await myContract.methods.getValidatorsCount().call();
    const operator_assets = [];
    for (let i = 0; i < validatorCount; i++) {
      const validatorEthAddress = await myContract.methods.registeredValidators(i).call();
      const validatorExoAddress = await myContract.methods.ethToExocoreAddress(validatorEthAddress).call();
      const assetsByOperator = [];
      for (let j = 0; j < supportedTokensCount; j++) {
        // do not reuse the older array since it has been sorted.
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        let matchingEntries = slashProportions.filter(
          (element) => element.token === tokenAddress && element.impacted_validators.includes(validatorExoAddress)
        );
        let totalSlashing = new Decimal(0);
        let selfSlashing = new Decimal(0);
        for(let k = 0; k < matchingEntries.length; k++) {
          let matchingEntry = matchingEntries[k];
          let delegation = await myContract.methods.delegations(
            matchingEntry.staker, validatorExoAddress, tokenAddress
          ).call();
          if (delegation > 0) {
            let slashing = new Decimal(delegation).mul(matchingEntry.proportion);
            totalSlashing = totalSlashing.plus(slashing);
            if (matchingEntry.staker == validatorEthAddress) {
              selfSlashing = slashing;
            }
          }
        }
        const delegationValue = new Decimal((await myContract.methods.delegationsByValidator(
          validatorExoAddress, tokenAddress
        ).call()).toString()).minus(totalSlashing);
        const selfDelegation = new Decimal((await myContract.methods.delegations(
          validatorEthAddress, validatorExoAddress, tokenAddress
        ).call()).toString()).minus(selfSlashing);

        const assetsByOperatorForAsset = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          info: {
            total_amount: delegationValue.toFixed(),
            pending_undelegation_amount: "0",
            total_share: delegationValue.toFixed(),
            operator_share: selfDelegation.toFixed(),
          }
        };
        assetsByOperator.push(assetsByOperatorForAsset);
        // break;
      }
      // sort for determinism
      assetsByOperator.sort((a, b) => {
        // the asset_id is guaranteed to be unique, so no further sorting is needed.
        if (a.asset_id < b.asset_id) {
          return -1;
        }
        if (a.asset_id > b.asset_id) {
          return 1;
        }
        return 0;
      });
      const assetsByOperatorWrapped = {
        operator: validatorExoAddress,
        assets_state: assetsByOperator
      };
      operator_assets.push(assetsByOperatorWrapped);
    }
    // sort for determinism
    operator_assets.sort((a, b) => {
      // the operator address is guaranteed to be unique, so no further sorting is needed.
      if (a.operator < b.operator) {
        return -1;
      }
      if (a.operator > b.operator) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.assets.operator_assets = operator_assets;

    // x/operator: operators (operator.go)
    if (!genesisJSON.app_state.operator.operators) {
      genesisJSON.app_state.operator.operators = [];
    }

    // x/dogfood: val_set (validators.go)
    if (!genesisJSON.app_state.dogfood) {
      throw new Error('The dogfood section is missing from the genesis file.');
    }
    if (!genesisJSON.app_state.dogfood.val_set) {
      genesisJSON.app_state.dogfood.val_set = [];
    }
    // check min_self_delegation
    const minSelfDelegation = new Decimal(genesisJSON.app_state.dogfood.params.min_self_delegation);
    // x/delegation: associations
    if (!genesisJSON.app_state.delegation.associations) {
      genesisJSON.app_state.delegation.associations = [];
    }
    let validators = [];
    const operators = [];
    const associations = [];
    const operatorsCount = await myContract.methods.getValidatorsCount().call();
    let dogfoodUSDValue = new Decimal(0);
    const operator_records = [];
    const opt_states = [];
    const avs_usd_values = [];
    const operator_usd_values = [];
    const chain_id_without_revision = getChainIDWithoutPrevision(genesisJSON.chain_id);
    const dogfoodAddr = generateAVSAddr(chain_id_without_revision);

    for (let i = 0; i < operatorsCount; i++) {
      // operators
      const opAddressHex = await myContract.methods.registeredValidators(i).call();
      const opAddressExo = await myContract.methods.ethToExocoreAddress(
        opAddressHex
      ).call();
      if (!isValidBech32(opAddressExo)) {
        console.log(`Skipping operator with invalid bech32 address: ${opAddressExo}`);
        continue;
      }
      const operatorInfo = await myContract.methods.validators(opAddressExo).call();
      const operator_info = {
        earnings_addr: opAddressExo,
        // approve_addr unset
        operator_meta_info: operatorInfo.name,
        client_chain_earnings_addr: {
          earning_info_list: [
            {
              lz_client_chain_id: clientChainInfo.layer_zero_chain_id,
              client_chain_earning_addr: opAddressHex,
            }
          ]
        },
        commission: {
          commission_rates: {
            rate: new Decimal(
              operatorInfo.commission.rate.toString()
            ).div('1e18').toFixed(),
            max_rate: new Decimal(
              operatorInfo.commission.maxRate.toString()
            ).div('1e18').toFixed(),
            max_change_rate: new Decimal(
              operatorInfo.commission.maxChangeRate.toString()
            ).div('1e18').toFixed(),
          },
          update_time: spawnDate,
        }
      }
      const operatorCleaned = {
        operator_address: opAddressExo,
        operator_info: operator_info
      }
      operators.push(operatorCleaned);
      // dogfood: val_set
      // TODO: once the oracle module is set up, move away from this solution
      // and instead, load the asset prices into the oracle module genesis
      // and let the dogfood module pull the vote power from the rest of the system
      // at genesis.
      let amount = new Decimal(0);
      let totalAmount = new Decimal(0);
      if (exchangeRates.length != supportedTokens.length) {
        throw new Error(
          `The number of exchange rates (${exchangeRates.length}) 
          does not match the number of supported tokens (${supportedTokens.length}).`
        );
      }
      for (let j = 0; j < supportedTokens.length; j++) {
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        let selfDelegationAmount = new Decimal((await myContract.methods.delegations(
            opAddressHex, opAddressExo, tokenAddress
        ).call()).toString());
        let matchingEntries = slashProportions.filter(
          (element) => element.token === tokenAddress && element.impacted_validators.includes(opAddressExo)
        );
        let totalSlashing = new Decimal(0);
        let selfSlashing = new Decimal(0);
        for(let k = 0; k < matchingEntries.length; k++) {
          let matchingEntry = matchingEntries[k];
          let delegation = await myContract.methods.delegations(
            matchingEntry.staker, opAddressExo, tokenAddress
          ).call();
          if (delegation > 0) {
            let slashing = new Decimal(delegation).mul(matchingEntry.proportion);
            totalSlashing = totalSlashing.plus(slashing);
            if (matchingEntry.staker == opAddressHex) {
              selfSlashing = slashing;
            }
          }
        }
        selfDelegationAmount = selfDelegationAmount.minus(selfSlashing);
        amount = amount.plus(
          selfDelegationAmount.
            div('1e' + decimals[j]).
            mul(exchangeRates[j].toFixed())
        );
        const perTokenDelegation = new Decimal((await myContract.methods.delegationsByValidator(
          opAddressExo, tokenAddress
        ).call()).toString()).minus(totalSlashing);
        totalAmount = totalAmount.plus(
          perTokenDelegation.
            div('1e' + decimals[j]).
            mul(exchangeRates[j].toFixed())
        );
        // break;
      }
      // only mark as validator if the amount is greater than min_self_delegation
      if (amount.gte(minSelfDelegation)) {
        validators.push({
          public_key: operatorInfo.consensusPublicKey,
          power: totalAmount,  // do not convert to int yet.
        });
        // set the consensus key, opted info, and USD value for the valid operators and dogfood AVS.
        // consensus public key
        const chains = [];
        chains.push({
          chain_id: chain_id_without_revision,
          consensus_key: operatorInfo.consensusPublicKey,
        });
        operator_records.push({
          operator_address: opAddressExo,
          chains: chains
        });
        // opted info
        const key = getJoinedStoreKey(opAddressExo, dogfoodAddr);
        const DefaultOptedOutHeight = BigInt("18446744073709551615");
        opt_states.push({
          key: key,
          opt_info: {
            opted_in_height: height,
            opted_out_height: DefaultOptedOutHeight.toString(),
          }
        });
        // USD value for the operators
        const usdValuekey = getJoinedStoreKey(dogfoodAddr, opAddressExo);
        operator_usd_values.push({
          key: usdValuekey,
          opted_usd_value: {
            self_usd_value: amount.toFixed(),
            total_usd_value: totalAmount.toFixed(),
            active_usd_value: totalAmount.toFixed(),
          }
        });
        dogfoodUSDValue = dogfoodUSDValue.plus(totalAmount);
      } else {
        console.log(`Skipping operator ${opAddressExo} due to insufficient self delegation.`);
      }
      let stakerId = opAddressHex.toLowerCase() + clientChainSuffix;
      let association = {
        staker_id: stakerId,
        operator: opAddressExo,
      };
      associations.push(association);
    }
    // operators
    operators.sort((a, b) => {
      if (a.operator_address < b.operator_address) {
        return -1;
      }
      if (a.operator_address > b.operator_address) {
        return 1;
      }
      return 0;
    });
    // operator_records
    operator_records.sort((a, b) => {
      if (a.operator_address < b.operator_address) {
        return -1;
      }
      if (a.operator_address > b.operator_address) {
        return 1;
      }
      return 0;
    });
    // opt_states
    opt_states.sort((a, b) => {
      if (a.key < b.key) {
        return -1;
      }
      if (a.key > b.key) {
        return 1;
      }
      return 0;
    });
    // avs_usd_values
    avs_usd_values.push({
      avs_addr: dogfoodAddr,
      value: {
        amount: dogfoodUSDValue.toFixed(),
      },
    });
    // operator_usd_values
    operator_usd_values.sort((a, b) => {
      if (a.key < b.key) {
        return -1;
      }
      if (a.key > b.key) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.operator.operators = operators;
    genesisJSON.app_state.operator.operator_records = operator_records;
    genesisJSON.app_state.operator.opt_states = opt_states;
    genesisJSON.app_state.operator.avs_usd_values = avs_usd_values;
    genesisJSON.app_state.operator.operator_usd_values = operator_usd_values;
    // dogfood: val_set
    validators.sort((a, b) => {
      // even though public_key is unique, we have to still
      // check for power first. this is because we pick the top N
      // validators by power.
      // if the powers are equal, we sort by public_key in
      // ascending order.
      if (b.power.cmp(a.power) === 0) {
        if (a.public_key < b.public_key) {
          return -1;
        }
        if (a.public_key > b.public_key) {
          return 1;
        }
        return 0;
      }
      return b.power.cmp(a.power);
    });
    // pick top N by vote power
    validators = validators.slice(0, genesisJSON.app_state.dogfood.params.max_validators);
    let totalPower = 0;
    validators.forEach((val) => {
      // truncate
      val.power = val.power.toFixed(0);
      totalPower += parseInt(val.power, 10);
    });
    genesisJSON.app_state.dogfood.val_set = validators;
    genesisJSON.app_state.dogfood.params.asset_ids = assetIds;
    genesisJSON.app_state.dogfood.last_total_power = totalPower.toFixed();
    // associations: staker_id is unique, so no further sorting is needed.
    associations.sort((a, b) => {
      if (a.staker_id < b.staker_id) {
        return -1;
      }
      if (a.staker_id > b.staker_id) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.delegation.associations = associations;

    // iterate over all stakers, then all assets, then all operators
    const delegation_states = [];
    const stakers_by_operator = [];
    const stakerListMap = new Map();
    for (let i = 0; i < depositorsCount; i++) {
      const staker = await myContract.methods.depositors(i).call();
      const stakerId = staker.toLowerCase() + clientChainSuffix;

      for (let j = 0; j < supportedTokens.length; j++) {
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        const assetId = tokenAddress.toLowerCase() + clientChainSuffix;

        for (let k = 0; k < operatorsCount; k++) {
          const operatorEth = await myContract.methods.registeredValidators(k).call();
          const operator = await myContract.methods.ethToExocoreAddress(operatorEth).call();
          if (!isValidBech32(operator)) {
            console.log(`Skipping operator with invalid bech32 address: ${operator}`);
            continue;
          }
          let matchingEntries = slashProportions.filter(
            (element) => element.token === tokenAddress && element.impacted_validators.includes(operator)
          );
          let totalSlashing = new Decimal(0);
          let selfSlashing = new Decimal(0);
          for(let k = 0; k < matchingEntries.length; k++) {
            let matchingEntry = matchingEntries[k];
            let delegation = await myContract.methods.delegations(
              matchingEntry.staker, validatorExoAddress, tokenAddress
            ).call();
            if (delegation > 0) {
              let slashing = new Decimal(delegation).mul(matchingEntry.proportion);
              totalSlashing = totalSlashing.plus(slashing);
              if (matchingEntry.staker == validatorEthAddress) {
                selfSlashing = slashing;
              }
            }
          }
          const amount = new Decimal((await myContract.methods.delegations(
            staker, operator, tokenAddress
          ).call()).toString()).minus(totalSlashing);
          if (amount.isPositive()) {
            const key = getJoinedStoreKey(stakerId, assetId, operator);
            delegation_states.push({
              key: key,
              states: {
                undelegatable_share: amount.toFixed(),
                wait_undelegation_amount: "0"
              },
            });

            //map key
            const mapKey = getJoinedStoreKey(operator, assetId);
            if (!stakerListMap.has(mapKey)) {
              stakerListMap.set(mapKey, []);
            }
            stakerListMap.get(mapKey).push(stakerId);
          }
        }
        // break;
      }
      // break;
    }
    delegation_states.sort((a, b) => {
      if (a.key < b.key) {
        return -1;
      }
      if (a.key > b.key) {
        return 1;
      }
      return 0;
    });

    stakerListMap.forEach((value, key) => {
      stakers_by_operator.push({
        key: key,
        stakers: value,
      });
    });
    stakers_by_operator.sort((a, b) => {
      if (a.key < b.key) {
        return -1;
      }
      if (a.key > b.key) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.delegation.delegation_states = delegation_states;
    genesisJSON.app_state.delegation.stakers_by_operator = stakers_by_operator;

    // x/oracle - native restaking for ETH
    genesisJSON.app_state.oracle.staker_list_assets = [
      {
        asset_id: VIRTUAL_STAKED_ETH_ADDR.toLowerCase() + clientChainSuffix,
        staker_list: {
          staker_addrs: nativeTokenDepositors,
        }
      }
    ];
    genesisJSON.app_state.oracle.staker_infos_assets = [{
      asset_id: VIRTUAL_STAKED_ETH_ADDR.toLowerCase() + clientChainSuffix,
      staker_infos: staker_infos,
    }];

    // add the native chain and at the end so that count-related issues don't arise.
    genesisJSON.app_state.assets.client_chains.push(nativeChain);
    genesisJSON.app_state.assets.tokens.push(nativeAsset);
    // TODO: copy the staking data over from the previous genesis, if any.
    genesisJSON.app_state.dogfood.params.asset_ids.push(
      nativeAsset.asset_basic_info.address.toLowerCase() + '_0x' +
      nativeAsset.asset_basic_info.layer_zero_chain_id.toString(16)
    );

    await fs.writeFile(
      INTEGRATION_RESULT_GENESIS_FILE_PATH,
      jsonBig.stringify(genesisJSON, null, 2)
    );
    console.log('Genesis file updated successfully.');
  } catch (error) {
    console.error(
      'Error updating genesis file:', error.message, '\nstack trace:', error.stack
    );
  }
};

updateGenesisFile();