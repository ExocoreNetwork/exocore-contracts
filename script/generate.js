// conventions are that the snake_case is within the JSON
// and variables within this file are title case

// global constants include the chain information
const clientChainInfo = {
    'name': 'Ethereum localnet',
    'meta_info': 'Ethereum-based localnet running on Anvil',
    'finalization_blocks': 10,
    'layer_zero_chain_id': 101, // TODO
    'address_length': 20,
  };

const tokenMetaInfos = [
  'Sample token 1', 'Sample token 2'
];

const exocoreBech32Prefix = 'exo';

require('dotenv').config();
let { decode } = require('bech32');
const fs = require('fs').promises;
const { Web3 } = require('web3');
const Decimal = require('decimal.js');

const isValidBech32 = (address) => {
  try {
    const { prefix, words } = decode(address);
    if (!prefix || !words.length) {
      return false;
    }
    return prefix === exocoreBech32Prefix;
  } catch (error) {
    // If there's any error in decoding, return false
    return false;
  }
}


// Load variables from .env file
const { NODE_URL, CONTRACT_ADDRESS, GENESIS_FILE_PATH, EXCHANGE_RATES } = process.env;

async function updateGenesisFile() {
  try {
    // Read and parse the ABI from abi.json
    const abiPath = './out/Bootstrap.sol/Bootstrap.json';
    const contractABI = JSON.parse(await fs.readFile(abiPath, 'utf8')).abi;

    // Set up Web3
    const web3 = new Web3(NODE_URL);

    // Create contract instance
    const myContract = new web3.eth.Contract(contractABI, CONTRACT_ADDRESS);

    // Read exchange rates
    const exchangeRates = EXCHANGE_RATES.split(',').map(Decimal);

    // Read the genesis file
    const genesisData = await fs.readFile(GENESIS_FILE_PATH);
    const genesisJSON = JSON.parse(genesisData);

    const chainId = genesisJSON.chain_id;
    const bootstrapped = await myContract.methods.bootstrapped().call();
    if (bootstrapped) {
      throw new Error('The contract has already been bootstrapped.');
    }

    // Set spawn time
    const spawnTime = await myContract.methods.exocoreSpawnTime().call();
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
    if (!genesisJSON.app_state.assets.tokens) {
      genesisJSON.app_state.assets.tokens = [];
    }
    const supportedTokensCount = await myContract.methods.getWhitelistedTokensCount().call();
    if (supportedTokensCount != tokenMetaInfos.length) {
      throw new Error(
        `The number of tokens in the contract (${supportedTokensCount}) 
        does not match the number of token meta infos (${tokenMetaInfos.length}).`
      );
    }
    const decimals = [];
    const supportedTokens = [];
    const assetIds = [];
    for (let i = 0; i < supportedTokensCount; i++) {
      let token = await myContract.methods.getWhitelistedTokenAtIndex(i).call();
      const tokenCleaned = {
        asset_basic_info: {
          name: token.name,
          symbol: token.symbol,
          address: token.tokenAddress,
          decimals: token.decimals.toString(),
          total_supply: token.totalSupply.toString(),
          layer_zero_chain_id: clientChainInfo.layer_zero_chain_id,
          // exocore_chain_index unused
          meta_info: tokenMetaInfos[i],
        },
        // set this to 0 intentionally, since the total amount will be provided
        // by the deposits
        staking_total_amount: "0",
      };
      supportedTokens[i] = tokenCleaned;
      decimals.push(token.decimals);
      assetIds.push(token.tokenAddress.toLowerCase() + clientChainSuffix);
      // break;
    }
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

    // x/assets: deposits (staker_asset.go)
    if (!genesisJSON.app_state.assets.deposits) {
      genesisJSON.app_state.assets.deposits = [];
    }
    const depositorsCount = await myContract.methods.getDepositorsCount().call();
    const deposits = [];
    for (let i = 0; i < depositorsCount; i++) {
      const stakerAddress = await myContract.methods.depositors(i).call();
      const depositsByStaker = [];
      for (let j = 0; j < supportedTokensCount; j++) {
        // do not reuse the older array since it has been sorted.
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        const depositValue = await myContract.methods.totalDepositAmounts(
          stakerAddress, tokenAddress
        ).call();
        const depositByStakerForAsset = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          info: {
            total_deposit_amount: depositValue.toString(),
            withdrawable_amount: depositValue.toString(),
            wait_unbonding_amount: "0",
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

    // x/operator: operators (operator.go)
    if (!genesisJSON.app_state.operator.operators) {
      genesisJSON.app_state.operator.operators = [];
    }
    // x/operator: operator_records (consensus_keys.go)
    if (!genesisJSON.app_state.operator.operator_records) {
      genesisJSON.app_state.operator.operator_records = [];
    }
    // x/dogfood: initial_val_set (validators.go)
    if (!genesisJSON.app_state.dogfood) {
      throw new Error('The dogfood section is missing from the genesis file.');
    }
    if (!genesisJSON.app_state.dogfood.initial_val_set) {
      genesisJSON.app_state.dogfood.initial_val_set = [];
    }
    const validators = [];
    const operators = [];
    const operatorRecords = [];
    const operatorsCount = await myContract.methods.getOperatorsCount().call();
    for (let i = 0; i < operatorsCount; i++) {
      // operators
      const operatorAddress = await myContract.methods.registeredOperators(i).call();
      const opAddressBech32 = await myContract.methods.ethToExocoreAddress(
        operatorAddress
      ).call();
      if (!isValidBech32(opAddressBech32)) {
        console.log(`Skipping operator with invalid bech32 address: ${opAddressBech32}`);
        continue;
      }
      const operatorInfo = await myContract.methods.operators(opAddressBech32).call();
      const operatorCleaned = {
        earnings_addr: opAddressBech32,
        // approve_addr unset
        operator_meta_info: operatorInfo.name,
        client_chain_earnings_addr: {
          earning_info_list: [
            {
              lz_client_chain_id: clientChainInfo.layer_zero_chain_id,
              client_chain_earning_addr: operatorAddress,
            }
          ]
        }
      }
      operators.push(operatorCleaned);
      // operator_records
      const operatorRecord = {
        operator_address: opAddressBech32,
        chains: [
          {
            chain_id: chainId,  // this is the exocore chain id
            consensus_key: operatorInfo.consensusPublicKey,
          }
        ],
      };
      operatorRecords.push(operatorRecord);
      // dogfood: initial_val_set
      // TODO: once the oracle module is set up, move away from this solution
      // and instead, load the asset prices into the oracle module genesis
      // and let the dogfood module pull the vote power from the rest of the system
      // at genesis.
      let amount = new Decimal(0);
      for(let j = 0; j < supportedTokens.length; j++) {
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        const perTokenDelegation = await myContract.methods.delegationsByOperator(
          opAddressBech32, tokenAddress
        ).call();
        amount = amount.plus(
          new Decimal(perTokenDelegation.toString()).
            div('1e' + decimals[j]).
            mul(exchangeRates[j].toString())
        );
        // break;
      }
      validators.push({
        public_key: operatorInfo.consensusPublicKey,
        power: amount,  // do not convert to int yet.
      });
      // break;
    }
    // operators
    operators.sort((a, b) => {
      if (a.earnings_addr < b.earnings_addr) {
        return -1;
      }
      if (a.earnings_addr > b.earnings_addr) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.operator.operators = operators;
    // operator_records
    operatorRecords.sort((a, b) => {
      if (a.operator_address < b.operator_address) {
        return -1;
      }
      if (a.operator_address > b.operator_address) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.operator.operator_records = operatorRecords;
    // dogfood: initial_val_set
    validators.sort((a, b) => {
      return b.power.cmp(a.power);
    });
    validators.slice(0, genesisJSON.app_state.dogfood.params.max_validators);
    validators.forEach((val) => {
      val.power = val.power.toFixed(0);
    });
    genesisJSON.app_state.dogfood.initial_val_set = validators;
    genesisJSON.app_state.dogfood.params.asset_ids = assetIds;

    // x/delegation: delegations_by_staker_asset_operator (delegation_state.go)
    if (!genesisJSON.app_state.delegation.delegations) {
      genesisJSON.app_state.delegation.delegations = [];
    }
    // iterate over all stakers, then all assets, then all operators
    const baseLevel = [];
    for(let i = 0; i < depositorsCount; i++) {
      const staker = await myContract.methods.depositors(i).call();
      let level1 = {
        staker_id: staker.toLowerCase() + clientChainSuffix,
        delegations: [],
      }
      for(let j = 0; j < supportedTokens.length; j++) {
        const tokenAddress =
          (await myContract.methods.getWhitelistedTokenAtIndex(j).call()).tokenAddress;
        let level2 = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          per_operator_amounts: [],
        }
        for(let k = 0; k < operatorsCount; k++) {
          const operatorEth = await myContract.methods.registeredOperators(k).call();
          const operator = await myContract.methods.ethToExocoreAddress(operatorEth).call();
          if (!isValidBech32(operator)) {
            console.log(`Skipping operator with invalid bech32 address: ${operator}`);
            continue;
          }
          const amount = await myContract.methods.delegations(
            staker, operator, tokenAddress
          ).call();
          if (amount.toString() > 0) {
            let level3 = {
              key: operator,
              value: {
                amount: amount.toString()
              }
            }
            level2.per_operator_amounts.push(level3);
            // break;
          }
        }
        level2.per_operator_amounts.sort((a, b) => {
          if (a.key < b.key) {
            return -1;
          }
          if (a.key > b.key) {
            return 1;
          }
          return 0;
        });
        level1.delegations.push(level2);
        // break;
      }
      level1.delegations.sort((a, b) => {
        if (a.asset_id < b.asset_id) {
          return -1;
        }
        if (a.asset_id > b.asset_id) {
          return 1;
        }
        return 0;
      });
      baseLevel.push(level1);
      // break;
    }
    baseLevel.sort((a, b) => {
      // the staker_id is guaranteed to be unique, so no further sorting is needed.
      if (a.staker_id < b.staker_id) {
        return -1;
      }
      if (a.staker_id > b.staker_id) {
        return 1;
      }
      return 0;
    });
    genesisJSON.app_state.delegation.delegations = baseLevel;

    await fs.writeFile(GENESIS_FILE_PATH, JSON.stringify(genesisJSON, null, 2));
    console.log('Genesis file updated successfully.');
  } catch (error) {
    console.error('Error updating genesis file:', error.message);
  }
}

updateGenesisFile();