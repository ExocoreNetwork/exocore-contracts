pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IExocoreGateway.sol";
import "../src/storage/GatewayStorage.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import {BaseScript} from "./BaseScript.sol";

contract DepositScript is BaseScript {
    using AddressCast for address;

    function setUp() public virtual override {
        super.setUp();

        string memory deployedContracts = vm.readFile("script/deployedContracts.json");

        clientGateway =
            IClientChainGateway(payable(stdJson.readAddress(deployedContracts, ".clientChain.clientChainGateway")));
        require(address(clientGateway) != address(0), "clientGateway address should not be empty");

        clientChainLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".clientChain.lzEndpoint"));
        require(address(clientChainLzEndpoint) != address(0), "clientChainLzEndpoint address should not be empty");

        restakeToken = ERC20PresetFixedSupply(stdJson.readAddress(deployedContracts, ".clientChain.erc20Token"));
        require(address(restakeToken) != address(0), "restakeToken address should not be empty");

        vault = IVault(stdJson.readAddress(deployedContracts, ".clientChain.resVault"));
        require(address(vault) != address(0), "vault address should not be empty");

        exocoreGateway = IExocoreGateway(payable(stdJson.readAddress(deployedContracts, ".exocore.exocoreGateway")));
        require(address(exocoreGateway) != address(0), "exocoreGateway address should not be empty");

        exocoreLzEndpoint = ILayerZeroEndpointV2(stdJson.readAddress(deployedContracts, ".exocore.lzEndpoint"));
        require(address(exocoreLzEndpoint) != address(0), "exocoreLzEndpoint address should not be empty");

        if (!useExocorePrecompileMock) {
            _bindPrecompileMocks();
        }

        // transfer some gas fee to depositor, relayer and exocore gateway
        clientChain = vm.createSelectFork(clientChainRPCURL);
        _topUpPlayer(clientChain, address(0), deployer, depositor.addr, 0.2 ether);
        _topUpPlayer(clientChain, address(restakeToken), exocoreValidatorSet, depositor.addr, 2 * DEPOSIT_AMOUNT);

        exocore = vm.createSelectFork(exocoreRPCURL);
        _topUpPlayer(exocore, address(0), exocoreGenesis, relayer.addr, 0.2 ether);
        _topUpPlayer(exocore, address(0), exocoreGenesis, address(exocoreGateway), 2 ether);
    }

    function run() public {
        bytes memory msg_ = abi.encodePacked(
            GatewayStorage.Action.REQUEST_DEPOSIT,
            abi.encodePacked(bytes32(bytes20(address(restakeToken)))),
            abi.encodePacked(bytes32(bytes20(depositor.addr))),
            uint256(DEPOSIT_AMOUNT)
        );

        vm.selectFork(clientChain);
        vm.startBroadcast(depositor.privateKey);

        restakeToken.approve(address(vault), type(uint256).max);

        uint256 nativeFee = clientGateway.quote(msg_);
        console.log("l0 native fee:", nativeFee);

        clientGateway.deposit{value: nativeFee}(address(restakeToken), DEPOSIT_AMOUNT);

        vm.stopBroadcast();

        if (useEndpointMock) {
            vm.selectFork(exocore);
            vm.startBroadcast(relayer.privateKey);
            uint64 nonce = exocoreGateway.nextNonce(clientChainId, address(clientGateway).toBytes32());
            exocoreLzEndpoint.lzReceive{gas: 500000}(
                Origin(clientChainId, address(clientGateway).toBytes32(), nonce),
                address(exocoreGateway),
                GUID.generate(
                    nonce, clientChainId, address(clientGateway), exocoreChainId, address(exocoreGateway).toBytes32()
                ),
                msg_,
                bytes("")
            );
            vm.stopBroadcast();
        }
    }
}
