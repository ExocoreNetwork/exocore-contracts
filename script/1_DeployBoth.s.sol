pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../test/mocks/NonShortCircuitLzEndpointMock.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";

contract DeployScript is Script {
    Player[] players;
    Player clientChainDeployer;
    Player exocoreValidatorSet;
    Player exocoreDeployer;
    Player exocoreGenesis;

    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    address[] vaults;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpoint clientChainLzEndpoint;
    ILayerZeroEndpoint exocoreLzEndpoint;

    uint16 exocoreChainId = 10259;
    uint16 clientChainId = 10161;

    uint256 clientChain;
    uint256 exocore;

    ERC20PresetFixedSupply restakeToken = ERC20PresetFixedSupply(address(0x83E6850591425e3C1E263c054f4466838B9Bd9e4));

    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        clientChainDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_TWO_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);
        
        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        exocoreGenesis.privateKey = vm.envUint("EXOCORE_GENESIS_PRIVATE_KEY");
        exocoreGenesis.addr = vm.addr(exocoreGenesis.privateKey);

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
        
        // transfer some gas fee to exocore validator set address
        clientChain = vm.createSelectFork(clientChainRPCURL);
        vm.startBroadcast(clientChainDeployer.privateKey);
        if (exocoreValidatorSet.addr.balance < 0.1 ether) {
            (bool sent, ) = exocoreValidatorSet.addr.call{value: 0.1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
        console.log("client chain deployer balance:", clientChainDeployer.addr.balance);
        console.log("client chain exocore validator set balance", exocoreValidatorSet.addr.balance);

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (exocoreDeployer.addr.balance < 1 ether) {
            (bool sent, ) = exocoreDeployer.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (exocoreValidatorSet.addr.balance < 1 ether) {
            (bool sent, ) = exocoreValidatorSet.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
        console.log("exocore deployer balance:", exocoreDeployer.addr.balance);
        console.log("exocore validator set balance", exocoreValidatorSet.addr.balance);
    }

    function run() public {
        // deploy on client chain via rpc
        vm.selectFork(clientChain);
        vm.startBroadcast(clientChainDeployer.privateKey);
        // prepare outside contracts like ERC20 token contract and layerzero endpoint contract
        // restakeToken = new ERC20PresetFixedSupply(
        //     "exoETH",
        //     "exoETH",
        //     1e34,
        //     exocoreValidatorSet.addr
        // );
        clientChainLzEndpoint = new NonShortCircuitLzEndpointMock(clientChainId, exocoreValidatorSet.addr);
        // deploy and initialize client chain contracts
        ProxyAdmin clientChainProxyAdmin = new ProxyAdmin();
        whitelistTokens.push(address(restakeToken));
        ClientChainGateway clientGatewayLogic = new ClientChainGateway();
        clientGateway = ClientChainGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic), 
                        address(clientChainProxyAdmin), 
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens,
                            address(clientChainLzEndpoint),
                            exocoreChainId
                        )
                    )
                )
            )   
        );
        Vault vaultLogic = new Vault();
        vault = Vault(
            address(
                new TransparentUpgradeableProxy(
                    address(vaultLogic), 
                    address(clientChainProxyAdmin),
                    abi.encodeWithSelector(
                        vaultLogic.initialize.selector,
                        address(restakeToken),
                        address(clientGateway)
                    )
                )
            )
        );
        vm.stopBroadcast();

        // deploy on Exocore via rpc
        vm.selectFork(exocore);
        vm.startBroadcast(exocoreDeployer.privateKey);
        // prepare outside contracts like layerzero endpoint contract
        exocoreLzEndpoint = new NonShortCircuitLzEndpointMock(exocoreChainId, exocoreValidatorSet.addr);
        // deploy Exocore network contracts
        ProxyAdmin exocoreProxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreGateway = ExocoreGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(exocoreGatewayLogic),
                        address(exocoreProxyAdmin), 
                        abi.encodeWithSelector(
                            exocoreGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            address(exocoreLzEndpoint)
                        )
                    )
                )
            )
        );
        vm.stopBroadcast();

        // setup client chain contracts state
        vm.selectFork(clientChain);
        // Exocore validator set should be the owner of these contracts and only owner could setup contracts state
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        // set the destination endpoint for corresponding destinations in endpoint mock
        NonShortCircuitLzEndpointMock(address(clientChainLzEndpoint)).setDestLzEndpoint(address(exocoreGateway), address(exocoreLzEndpoint));
        // add token vaults to gateway
        vaults.push(address(vault));
        clientGateway.addTokenVaults(vaults);
        // as LzReceivers, gateway should set bytes(sourceChainGatewayAddress+thisAddress) as trusted remote to receive messages
        clientGateway.setTrustedRemote(exocoreChainId, abi.encodePacked(address(exocoreGateway), address(clientGateway)));
        vm.stopBroadcast();

        // setup Exocore testnet contracts state
        vm.selectFork(exocore);
        // Exocore validator set should be the owner of these contracts and only owner could setup contracts state
        vm.startBroadcast(exocoreValidatorSet.privateKey);
        // set the destination endpoint for corresponding destinations in endpoint mock
        NonShortCircuitLzEndpointMock(address(exocoreLzEndpoint)).setDestLzEndpoint(address(clientGateway), address(clientChainLzEndpoint));        
        exocoreGateway.setTrustedRemote(clientChainId, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        vm.stopBroadcast();

        string memory deployedContracts = "deployedContracts";
        string memory clientChainContracts = "clientChainContracts";
        string memory exocoreContracts = "exocoreContracts";
        vm.serializeAddress(clientChainContracts, "lzEndpoint", address(clientChainLzEndpoint));
        vm.serializeAddress(clientChainContracts, "clientChainGateway", address(clientGateway));
        vm.serializeAddress(clientChainContracts, "resVault", address(vault));
        vm.serializeAddress(clientChainContracts, "erc20Token", address(restakeToken));
        string memory clientChainContractsOutput = vm.serializeAddress(clientChainContracts, "proxyAdmin", address(clientChainProxyAdmin));

        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));
        string memory exocoreContractsOutput = vm.serializeAddress(exocoreContracts, "proxyAdmin", address(exocoreProxyAdmin));

        vm.serializeString(deployedContracts, "clientChain", clientChainContractsOutput);
        string memory finalJson = vm.serializeString(deployedContracts, "exocore", exocoreContractsOutput);
        
        vm.writeJson(finalJson, "script/deployedContracts.json");
    }
}
