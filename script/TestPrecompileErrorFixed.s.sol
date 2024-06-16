pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";

import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/IVault.sol";

import "../src/interfaces/precompiles/IAssets.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
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

    uint256 constant TEST_DEPOSIT_AMOUNT = 100;
    uint256 constant TEST_WITHDRAWAL_AMOUNT = 123;

    function setUp() public virtual override {
        super.setUp();

        exocoreRPCURL = vm.envString("EXOCORE_LOCAL_RPC");

        restakeToken = ERC20PresetFixedSupply(erc20TokenAddress);
        clientChainLzEndpoint = NonShortCircuitEndpointV2Mock(address(0xa));
        clientGateway = ClientChainGateway(payable(address(0xb)));

        string memory testContracts = vm.readFile("script/testContracts.json");

        exocoreGateway = IExocoreGateway(payable(stdJson.readAddress(testContracts, ".exocore.exocoreGateway")));
        require(address(exocoreGateway) != address(0), "exocoreGateway address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(testContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocoreLzEndpoint address should not be empty");

        exocore = vm.createSelectFork(exocoreRPCURL);
        vm.startBroadcast(exocoreGenesis.privateKey);
        if (depositor.addr.balance < 1 ether) {
            (bool sent,) = depositor.addr.call{value: 2 ether}("");
            require(sent, "Failed to send Ether");
        }
        if (address(exocoreGateway).balance < 1 ether) {
            (bool sent,) = address(exocoreGateway).call{value: 2 ether}("");
            require(sent, "Failed to send Ether");
        }
        vm.stopBroadcast();

        // bind precompile mock contracts code to constant precompile address so that local simulation could pass
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }

    function run() public {
        bytes memory depositMsg = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(depositor.addr))),
            uint256(TEST_DEPOSIT_AMOUNT)
        );

        vm.selectFork(exocore);
        vm.startBroadcast(depositor.privateKey);
        uint64 nonce = exocoreGateway.nextNonce(clientChainId, address(clientGateway).toBytes32());
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), nonce),
            address(exocoreGateway),
            GUID.generate(
                nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
            ),
            depositMsg,
            bytes("")
        );
        vm.stopBroadcast();

        bytes memory withdrawMsg = abi.encodePacked(
            GatewayStorage.Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(depositor.addr))),
            uint256(TEST_WITHDRAWAL_AMOUNT)
        );

        vm.selectFork(exocore);
        vm.startBroadcast(depositor.privateKey);
        nonce = exocoreGateway.nextNonce(clientChainId, address(clientGateway).toBytes32());
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), nonce),
            address(exocoreGateway),
            GUID.generate(
                nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
            ),
            withdrawMsg,
            bytes("")
        );
        vm.stopBroadcast();
    }

}
