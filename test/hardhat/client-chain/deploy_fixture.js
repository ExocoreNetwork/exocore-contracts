require("dotenv").config();

const exocoreChainId = 0;
const clientChainId = 101;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

async function deployFixture() {
    const [deployer, exocoreValidatorSet, depositor] = await ethers.getSigners();
    
    const {ERC20TokenContract, lzEndpointMockContract} = await prepareEnvironment(exocoreValidatorSet);

    const proxyAdmin = await ethers.getContractFactory("ProxyAdmin");
    const proxyAdminContract = await proxyAdmin.connect(deployer).deploy();
    await proxyAdminContract.waitForDeployment();

    console.log("start deploying gateway logic contract")
    const gatewayLogic = await ethers.getContractFactory("ClientChainGateway");
    const gatewayLogicContract = await gatewayLogic.connect(deployer).deploy();
    await gatewayLogicContract.waitForDeployment();

    console.log("start deploying gateway proxy contract")
    const gatewayProxy = await ethers.getContractFactory("TransparentUpgradeableProxy");
    const gatewayProxyContract = await gatewayProxy.connect(deployer).deploy(
        gatewayLogicContract.target,
        proxyAdminContract.target,
        gatewayLogicContract.interface.encodeFunctionData(
            "initialize", 
            [
                exocoreValidatorSet.address,
                [ ERC20TokenContract.target ],
                lzEndpointMockContract.target,
                exocoreChainId
            ]
        )
    );
    await gatewayProxyContract.waitForDeployment();
    const gatewayContract = gatewayLogicContract.attach(gatewayProxyContract.target);
    console.log("finish deploying gateway proxy contract");
    
    console.log("start deploying vault logic contract")
    const vaultLogic = await ethers.getContractFactory("Vault");
    const vaultLogicContract = await vaultLogic.connect(deployer).deploy();
    await vaultLogicContract.waitForDeployment();
    
    console.log("start deploying vault proxy contract")
    const vaultProxy = await ethers.getContractFactory("TransparentUpgradeableProxy");
    const vaultProxyContract = await vaultProxy.connect(deployer).deploy(
        vaultLogicContract.target,
        proxyAdminContract.target,
        vaultLogicContract.interface.encodeFunctionData(
            "initialize",
            [
                ERC20TokenContract.target,
                gatewayContract.target
            ]
        )
    );
    await vaultProxyContract.waitForDeployment();
    const vaultContract = vaultLogicContract.attach(vaultProxyContract.target);
    
    console.log("add vaults to gateway")
    await gatewayContract.connect(exocoreValidatorSet).addTokenVaults([vaultContract.target]);

    return {
        ERC20TokenContract,
        lzEndpointMockContract,
        proxyAdminContract,
        gatewayContract,
        vaultContract,
        deployer,
        exocoreValidatorSet,
        depositor
    }
}

async function prepareEnvironment(exocoreValidatorSet) {
    const ERC20Token = await ethers.getContractFactory("ERC20PresetFixedSupply");
    const ERC20TokenContract = await ERC20Token.deploy(
        "rest",
        "rest",
        1e8,
        exocoreValidatorSet.address
    );
    await ERC20TokenContract.waitForDeployment();

    const lzEndpointMock = await ethers.getContractFactory("NonShortCircuitLzEndpointMock");
    const lzEndpointMockContract = await lzEndpointMock.deploy(clientChainId);
    await lzEndpointMockContract.waitForDeployment();

    return {ERC20TokenContract, lzEndpointMockContract};
}

module.exports = { deployFixture, exocoreChainId, clientChainId };
