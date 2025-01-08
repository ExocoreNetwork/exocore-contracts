require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-foundry");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.22",
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
    exocore_localnet: {
      chainId: 9000,
      url: "http://127.0.0.1:8545",
      chainId: 233,
      accounts: [
        process.env.LOCAL_EXOCORE_FUNDED_ACCOUNT_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_ONE_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_TWO_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_THREE_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_FOUR_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_FIVE_PRIVATE_KEY,
        process.env.TEST_ACCOUNT_SIX_PRIVATE_KEY,
      ]
    }
  }
};
