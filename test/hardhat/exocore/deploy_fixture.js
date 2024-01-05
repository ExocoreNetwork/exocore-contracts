require("dotenv").config();

const exocoreChainId = 0;
const clientChainId = 101;

async function deployFixture() {
    const [deployer, exocoreValidatorSet, depositor] = await ethers.getSigners();
    
    const lzEndpointMockContract = await prepareEnvironment(exocoreValidatorSet);

    const proxyAdmin = await ethers.getContractFactory("ProxyAdmin");
    const proxyAdminContract = await proxyAdmin.connect(deployer).deploy();
    await proxyAdminContract.waitForDeployment();

    console.log("start deploying gateway logic contract")
    const gatewayLogic = await ethers.getContractFactory("ExocoreGateway");
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
                lzEndpointMockContract.target,
            ]
        )
    );
    await gatewayProxyContract.waitForDeployment();
    const gatewayContract = gatewayLogicContract.attach(gatewayProxyContract.target);
    console.log("finish deploying gateway proxy contract");
    console.log("gateway contract address:", gatewayProxyContract.target);

    return {
        lzEndpointMockContract,
        proxyAdminContract,
        gatewayContract,
        deployer,
        exocoreValidatorSet,
        depositor
    }
}

async function prepareEnvironment(exocoreValidatorSet) {
    const lzEndpointMock = await ethers.getContractFactory("NonShortCircuitLzEndpointMock");
    const lzEndpointMockContract = await lzEndpointMock.deploy(clientChainId);
    await lzEndpointMockContract.waitForDeployment();

    return lzEndpointMockContract;
}

module.exports = { deployFixture, exocoreChainId, clientChainId };
