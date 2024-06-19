pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";

import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/IVault.sol";

import "../src/storage/GatewayStorage.sol";

import {NonShortCircuitEndpointV2Mock} from "../test/mocks/NonShortCircuitEndpointV2Mock.sol";
import {BaseScript} from "./BaseScript.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";

import "src/core/ClientChainGateway.sol";
import "src/core/ExocoreGateway.sol";

contract DepositScript is BaseScript {

    using AddressCast for address;

    uint256 constant WITHDRAWAL_AMOUNT = 123;

    function setUp() public virtual override {
        super.setUp();

        exocoreRPCURL = vm.envString("EXOCORE_LOCAL_RPC");

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restakeToken address should not be empty");

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (deployer.addr.balance < 1 ether) {
            (bool sent,) = deployer.addr.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();
    }

    function run() public {
        _deploy();

        string memory testContracts = "testContracts";
        string memory exocoreContracts = "exocoreContracts";

        vm.serializeAddress(exocoreContracts, "lzEndpoint", address(exocoreLzEndpoint));
        string memory exocoreContractsOutput =
            vm.serializeAddress(exocoreContracts, "exocoreGateway", address(exocoreGateway));

        string memory finalJson = vm.serializeString(testContracts, "exocore", exocoreContractsOutput);

        vm.writeJson(finalJson, "script/testContracts.json");
    }

    function _deploy() internal {
        clientChainLzEndpoint = NonShortCircuitEndpointV2Mock(address(0xa));
        clientGateway = ClientChainGateway(payable(address(0xb)));

        vm.selectFork(exocore);

        vm.startBroadcast(deployer.privateKey);
        exocoreLzEndpoint = new NonShortCircuitEndpointV2Mock(exocoreChainId, exocoreValidatorSet.addr);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway(address(exocoreLzEndpoint));
        exocoreGateway = ExocoreGateway(
            payable(address(new TransparentUpgradeableProxy(address(exocoreGatewayLogic), address(proxyAdmin), "")))
        );
        ExocoreGateway(payable(address(exocoreGateway))).initialize(payable(exocoreValidatorSet.addr));
        vm.stopBroadcast();

        vm.startBroadcast(exocoreValidatorSet.privateKey);
        exocoreGateway.setPeer(clientChainId, address(clientGateway).toBytes32());
        NonShortCircuitEndpointV2Mock(address(exocoreLzEndpoint)).setDestLzEndpoint(
            address(clientGateway), address(clientChainLzEndpoint)
        );
        vm.stopBroadcast();
    }

}
