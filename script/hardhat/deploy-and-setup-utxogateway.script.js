const { ethers } = require("hardhat");
const fs = require('fs');
const path = require('path');
const { assert } = require("console");

const ASSETS_PRECOMPILE_ADDRESS = "0x0000000000000000000000000000000000000804";
const DEPLOYED_CONTRACTS_PATH = path.join(__dirname, '../deployments/deployedContracts.json');

async function main() {
  const initialAccounts = await ethers.getSigners();
  const [deployer, owner, witness1] = initialAccounts;
  console.log("Deploying contracts with account:", deployer.address);

  // deployer is also the faucet
  faucet = deployer;

  // transfer 1 ether gas tokens to all accounts
  for (const account of initialAccounts) {
      const tx = await faucet.sendTransaction({
          to: account.address,
          value: ethers.parseEther("1"),
      });
      // wait until the transaction is mined but should not exceed 10 seconds
      await tx.wait();
      assert(await ethers.provider.getBalance(account.address) > 0, "no enough balance for account")
  }

  // Load existing deployments if any
  let deployedContracts = {};
  if (fs.existsSync(DEPLOYED_CONTRACTS_PATH)) {
    deployedContracts = JSON.parse(fs.readFileSync(DEPLOYED_CONTRACTS_PATH, 'utf8'));
  } else {
    console.log("Cannot find json file of deployed contracts")
  }

  try {
    // Check if contracts are already deployed
    if (deployedContracts.UTXOGateway) {
      console.log("Using existing UTXOGateway deployment:", deployedContracts.UTXOGateway);
      return;
    }

    // 1. Deploy UTXOGateway Logic
    console.log("\nDeploying UTXOGateway Logic...");
    const UTXOGatewayFactory = await ethers.getContractFactory("UTXOGateway");
    const utxoGatewayLogic = await UTXOGatewayFactory.connect(deployer).deploy();
    await utxoGatewayLogic.waitForDeployment();
    console.log("UTXOGateway Logic deployed to:", await utxoGatewayLogic.getAddress());

    // 2. Deploy ProxyAdmin
    console.log("\nDeploying ProxyAdmin...");
    const ProxyAdminFactory = await ethers.getContractFactory("ProxyAdmin");
    const proxyAdmin = await ProxyAdminFactory.connect(deployer).deploy();
    await proxyAdmin.waitForDeployment();
    console.log("ProxyAdmin deployed to:", await proxyAdmin.getAddress());

    // 3. Deploy Transparent Proxy
    console.log("\nDeploying Transparent Proxy...");
    const ProxyFactory = await ethers.getContractFactory("TransparentUpgradeableProxy");
    const utxoGatewayProxy = await ProxyFactory.deploy(
      await utxoGatewayLogic.getAddress(),
      await proxyAdmin.getAddress(),
      utxoGatewayLogic.interface.encodeFunctionData("initialize", [
        owner.address,
        [witness1.address],
        3  // requiredProofs
      ])
    );
    await utxoGatewayProxy.waitForDeployment();
    
    // Get UTXOGateway interface for the proxy
    const utxoGateway = UTXOGatewayFactory.attach(await utxoGatewayProxy.getAddress());
    console.log("UTXOGateway Proxy deployed to:", await utxoGateway.getAddress());

    // 4. Set UTXOGateway as authorized in Assets precompile
    console.log("\nAuthorizing UTXOGateway in Assets precompile...");
    const assetsPrecompile = await ethers.getContractAt("IAssets", ASSETS_PRECOMPILE_ADDRESS);
    const authTx = await assetsPrecompile.connect(deployer).updateAuthorizedGateways([await utxoGateway.getAddress()]);
    await authTx.wait();

    // 5. Activate staking for Bitcoin
    console.log("\nActivating staking for Bitcoin...");
    const activateTx = await utxoGateway.connect(owner).activateStakingForClientChain(1); // 1 for Bitcoin
    await activateTx.wait();

    // 6. Verify setup with assertions
    console.log("\nVerifying setup...");
    const [authSuccess, isAuthorized] = await assetsPrecompile.isAuthorizedGateway(await utxoGateway.getAddress());
    const [chainSuccess, isChainRegistered] = await assetsPrecompile.isRegisteredClientChain(1);

    // Assert the setup is correct
    assert(authSuccess && isAuthorized, "UTXOGateway is not properly authorized");
    assert(chainSuccess && isChainRegistered, "Bitcoin chain is not properly registered");
    console.log("✅ All assertions passed");

    // 7. Save deployment information
    const deploymentInfo = {
      network: network.name,
      utxoGatewayProxy: await utxoGateway.getAddress(),
      utxoGatewayLogic: await utxoGatewayLogic.getAddress(),
      proxyAdmin: await proxyAdmin.getAddress(),
      owner: owner.address,
      witnesses: [witness1.address],
      requiredProofs: 3,
      isAuthorized,
      isChainRegistered,
      timestamp: new Date().toISOString()
    };

    // Save detailed deployment info
    const deploymentsDir = path.join(__dirname, '../deployments');
    if (!fs.existsSync(deploymentsDir)) {
      fs.mkdirSync(deploymentsDir);
    }
    fs.writeFileSync(
      path.join(deploymentsDir, `utxo-gateway-${network.name}.json`),
      JSON.stringify(deploymentInfo, null, 2)
    );

    // Update deployedContracts.json
    deployedContracts.UTXOGateway = {
      proxy: await utxoGateway.getAddress(),
      implementation: await utxoGatewayLogic.getAddress(),
      proxyAdmin: await proxyAdmin.getAddress(),
      owner: owner.address,
      witnesses: [witness1.address],
    };

    fs.writeFileSync(
      DEPLOYED_CONTRACTS_PATH,
      JSON.stringify(deployedContracts, null, 2)
    );

    console.log("\nDeployment Summary:");
    console.log("-------------------");
    console.log(deploymentInfo);
    console.log("\n✅ Deployment successful and verified!");

  } catch (error) {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  }
}

// Use CommonJS exports
module.exports = main;

// Only run if script is run directly
if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
