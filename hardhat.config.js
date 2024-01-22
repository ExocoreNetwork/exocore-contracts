require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-foundry");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
  allowUnlimitedContractSize: true,
  networks: {
    hardhat: {
    },
    exocore_testnet: {
      chainId: 9000,
      url: "http://23.162.56.84:8545",
      accounts: [
        // process.env.EXOCORE_GENESIS_PRIVATE_KEY,
        // process.env.EXOCORE_VALIDATOR_SET_PRIVATE_KEY
      ]
    }
  }
};
