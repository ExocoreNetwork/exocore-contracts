const { expect } = require("chai");
require("dotenv").config();

describe("BTC Stake", () => {
    let proxyAdmin;
    let utxoGateway;
    let utxoGatewayLogic;
    let assetsPrecompile;
    let faucet;
    let deployer;
    let owner;
    let relayer;
    let staker;
    let witness1;
    let witness2;
    let witness3;

    const ASSETS_PRECOMPILE_ADDRESS = "0x0000000000000000000000000000000000000804";

    // Run once before all tests
    before(async () => {
        const initialAccounts = await ethers.getSigners();
        [deployer, owner, relayer, staker, witness1, witness2, witness3] = initialAccounts;

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
            expect(await ethers.provider.getBalance(account.address)).to.be.greaterThanOrEqual(ethers.parseEther("1"));
        }

        // Deploy and initialize UTXOGateway only if contract hasn't been deployed yet
        if (!utxoGateway) {
            // deploy the logic contract
            const utxoGatewayFactory = await ethers.getContractFactory("UTXOGateway");
            utxoGatewayLogic = await utxoGatewayFactory.connect(deployer).deploy();
            await utxoGatewayLogic.waitForDeployment();

            // deploy the proxy admin contract
            const proxyAdminFactory = await ethers.getContractFactory("ProxyAdmin");
            proxyAdmin = await proxyAdminFactory.connect(deployer).deploy();
            await proxyAdmin.waitForDeployment();

            // deploy the proxy contract
            const proxyFactory = await ethers.getContractFactory("TransparentUpgradeableProxy");
            const utxoGatewayProxy = await proxyFactory.deploy(
                utxoGatewayLogic.target,
                proxyAdmin.target,
                utxoGatewayLogic.interface.encodeFunctionData("initialize", [owner.address, [witness1.address, witness2.address, witness3.address], 2])
            );
            await utxoGatewayProxy.waitForDeployment();

            // set the proxy address to the UTXOGateway interface
            utxoGateway = utxoGatewayFactory.attach(utxoGatewayProxy.target);
        }

        // set the utxo gateway as authorized
        assetsPrecompile = await ethers.getContractAt("IAssets", ASSETS_PRECOMPILE_ADDRESS);
        const tx = await assetsPrecompile.connect(deployer).updateAuthorizedGateways([utxoGateway.target]);
        const receipt = await tx.wait();
        expect(receipt.status).to.be.equal(1);
    });

    it("should deploy the contract and successfully set the utxo gateway as authorized", async () => {
        expect(utxoGateway.target).to.be.properAddress;
        console.log("UTXOGateway deployed to:", utxoGateway.target);

        // assert owner is set
        expect(await utxoGateway.owner()).to.equal(owner.address);

        // assert witnesses are set
        expect(await utxoGateway.authorizedWitnesses(witness1.address)).to.be.true;
        expect(await utxoGateway.authorizedWitnesses(witness2.address)).to.be.true;
        expect(await utxoGateway.authorizedWitnesses(witness3.address)).to.be.true;

        // assert threshold is set
        expect(await utxoGateway.requiredProofs()).to.equal(2);

        // assert the utxo gateway is authorized
        const [success, authorized] = await assetsPrecompile.isAuthorizedGateway(utxoGateway.target);
        expect(success).to.be.true;
        expect(authorized).to.be.true;
    });
});
