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
  'Exocore testnet ETH', // first we did push exoETH
  'Lido wrapped staked ETH', // then push wstETH
];
// this must be in the same order as whitelistTokens
// they are provided because the symbol may not match what we are using from the price feeder.
// for example, exoETH is not a real token and we are using the price feed for ETH.
const tokenNamesForOracle = [
  'ETH', 'wstETH' // not case sensitive
]

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
const { CLIENT_CHAIN_RPC, BOOTSTRAP_ADDRESS, BASE_GENESIS_FILE_PATH, RESULT_GENESIS_FILE_PATH, EXCHANGE_RATES } = process.env;

const { keccak256 } = require('js-sha3');
const JSONbig = require('json-bigint')({ "useNativeBigInt": true });

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
    const myContract = new web3.eth.Contract(contractABI, BOOTSTRAP_ADDRESS);

    // Read exchange rates
    const exchangeRates = EXCHANGE_RATES.split(',').map(Decimal);

    // Read the genesis file
    const genesisData = await fs.readFile(BASE_GENESIS_FILE_PATH);
    const genesisJSON = JSONbig.parse(genesisData);

    const height = parseInt(genesisJSON.initial_height, 10);
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
      genesisJSON.app_state.oracle.params.token_feeders = genesisJSON.app_state.oracle.params.token_feeders.slice(0, 1);
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
      const oracleToken = {
        name: tokenNamesForOracle[i],
        chain_id: 1,  // constant intentionally, representing the first chain in the list
        contract_address: token.tokenAddress,
        active: true,
        asset_id: token.tokenAddress.toLowerCase() + clientChainSuffix,
        decimal: 8, // price decimals, not token decimals
      }
      genesisJSON.app_state.oracle.params.tokens.push(oracleToken);
      const oracleTokenFeeder = {
        token_id: (i + 1).toString(), // first is reserved
        rule_id: "1",
        start_round_id: "1",
        start_base_block: (height + 10000).toString(),
        interval: "30",
        end_block: "0",
      }
      genesisJSON.app_state.oracle.params.token_feeders.push(oracleTokenFeeder);
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
    // do not sort x/oracle params since the order is related for
    // the token objects and the token feeders.

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
        const withdrawableValue = await myContract.methods.withdrawableAmounts(
          stakerAddress, tokenAddress
        ).call();
        const depositByStakerForAsset = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          info: {
            total_deposit_amount: depositValue.toString(),
            withdrawable_amount: withdrawableValue.toString(),
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
        const delegationValue = await myContract.methods.delegationsByValidator(
          validatorExoAddress, tokenAddress
        ).call();
        const totalShare = new Decimal(delegationValue.toString());
        const selfDelegation = await myContract.methods.delegations(
          validatorEthAddress, validatorExoAddress, tokenAddress
        ).call();
        const selfShare = new Decimal(selfDelegation.toString());

        const assetsByOperatorForAsset = {
          asset_id: tokenAddress.toLowerCase() + clientChainSuffix,
          info: {
            total_amount: delegationValue.toString(),
            pending_undelegation_amount: "0",
            total_share: totalShare.toFixed(),
            operator_share: selfShare.toFixed(),
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
    const validators = [];
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
        const selfDelegationAmount = await myContract.methods.delegations(opAddressHex, opAddressExo, tokenAddress).call();
        amount = amount.plus(
          new Decimal(selfDelegationAmount.toString()).
            div('1e' + decimals[j]).
            mul(exchangeRates[j].toFixed())
        );
        const perTokenDelegation = await myContract.methods.delegationsByValidator(
          opAddressExo, tokenAddress
        ).call();
        totalAmount = totalAmount.plus(
          new Decimal(perTokenDelegation.toString()).
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
    validators.slice(0, genesisJSON.app_state.dogfood.params.max_validators);
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
          const amount = await myContract.methods.delegations(
            staker, operator, tokenAddress
          ).call();
          if (amount.toString() > 0) {
            const key = getJoinedStoreKey(stakerId, assetId, operator);
            const share = new Decimal(amount.toString());
            delegation_states.push({
              key: key,
              states: {
                undelegatable_share: share.toFixed(),
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

    await fs.writeFile(RESULT_GENESIS_FILE_PATH, JSONbig.stringify(genesisJSON, null, 2));
    console.log('Genesis file updated successfully.');
  } catch (error) {
    console.error('Error updating genesis file:', error.message);
    console.error('Stack trace:', error.stack); 
  }
}

updateGenesisFile();