pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import {NonShortCircuitEndpointV2Mock} from "test/mocks/NonShortCircuitEndpointV2Mock.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "test/mocks/ClaimRewardMock.sol";
import "test/mocks/DelegationMock.sol";
import "test/mocks/DepositWithdrawMock.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "./BaseScript.sol";

contract PrerequisitiesScript is BaseScript {
    function setUp() public virtual override {
        super.setUp();
    }

    function run() public {
        clientChain = vm.createSelectFork(clientChainRPCURL);

        vm.startBroadcast(deployer.privateKey);
        beaconOracle = EigenLayerBeaconOracle(0xd3D285cd1516038dAED61B8BF7Ae2daD63662492);
        (bool success,) = address(beaconOracle).call(abi.encodeWithSelector(beaconOracle.addTimestamp.selector, 1715918948));
        vm.stopPrank();
    }

    function _deployBeaconOracle() internal returns (EigenLayerBeaconOracle) {
        uint256 GENESIS_BLOCK_TIMESTAMP;

        if (block.chainid == 1) {
            GENESIS_BLOCK_TIMESTAMP = 1606824023;
        } else if (block.chainid == 5) {
            GENESIS_BLOCK_TIMESTAMP = 1616508000;
        } else if (block.chainid == 11155111) {
            GENESIS_BLOCK_TIMESTAMP = 1655733600;
        } else if (block.chainid == 17000) {
            GENESIS_BLOCK_TIMESTAMP = 1695902400;
        } else {
            revert("Unsupported chainId.");
        }

        EigenLayerBeaconOracle oracle = new EigenLayerBeaconOracle(GENESIS_BLOCK_TIMESTAMP);
        return oracle;
    }
}
