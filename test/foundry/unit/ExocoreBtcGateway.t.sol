// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "src/interfaces/precompiles/IAssets.sol";
import "src/interfaces/precompiles/IClaimReward.sol";
import "src/interfaces/precompiles/IDelegation.sol";
import {IExocoreBtcGateway} from "src/interfaces/IExocoreBtcGateway.sol";
import "src/core/ExocoreBtcGateway.sol";


contract ExocoreBtcGatewayTest is IExocoreBtcGateway,Test {
    ExocoreBtcGateway exocoreBtcGateway;
    address  BTC_ADDR = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    bytes BTC_TOKEN = abi.encodePacked(BTC_ADDR);
    address payable validator = payable(address(0x1234));
    address deployer = address(0x5678);
    bytes btcAddress = "btcAddress";
    bytes exocoreAddress = "exocoreAddress";
    bytes operator = "operator";
    uint256 amount = 1000;

    function setUp() public {
        // bind precompile mock contracts code to constant precompile address
        bytes memory AssetsContractCode = vm.getDeployedCode("ASSETS_CONTRACT_Mock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsContractCode);

        bytes memory ClaimRewardContractCode = vm.getDeployedCode("CLAIM_REWARD_CONTRACT_Mock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, ClaimRewardContractCode);

        bytes memory DelegationContractCode = vm.getDeployedCode("DELEGATION_CONTRACT_Mock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationContractCode);


        exocoreBtcGateway = new ExocoreBtcGateway(2);
        exocoreBtcGateway.initialize(validator);
    }

    function testRegisterAddress() public {
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        bytes memory registeredExocoreAddress = exocoreBtcGateway.getBtcAddress(exocoreAddress);
        assertEq(registeredExocoreAddress, btcAddress);
    }

    function testDepositTo() public {
        InterchainMsg memory msg = InterchainMsg({
            srcChainID: 1,
            dstChainID: 2,
            srcAddress: btcAddress,
            dstAddress: exocoreAddress,
            token: BTC_ADDR,
            amount: amount,
            nonce: 1,
            txHash: "txHash",
            payload: ""
        });

        bytes memory signature = "signature";
        exocoreBtcGateway.depositTo(msg, signature);

        (bool processed, uint256 timestamp) = exocoreBtcGateway.processedBtcTxs(msg.txHash);
        assertTrue(processed);
        assertGt(timestamp, 0);
    }

    function testDelegateTo() public {
        exocoreBtcGateway.delegateTo(BTC_ADDR, exocoreAddress, operator, amount);
        // Add assertions to validate the delegation
    }

    function testUndelegateFrom() public {
        exocoreBtcGateway.undelegateFrom(BTC_ADDR, exocoreAddress, operator, amount);
        // Add assertions to validate the undelegation
    }

    function testWithdrawPrincipal() public {
        exocoreBtcGateway.withdrawPrincipal(BTC_ADDR, exocoreAddress, amount);
        // Add assertions to validate the principal withdrawal
    }

    function testWithdrawReward() public {
        exocoreBtcGateway.withdrawReward(BTC_ADDR, exocoreAddress, amount);
        // Add assertions to validate the reward withdrawal
    }

    function testDepositThenDelegateTo() public {
        InterchainMsg memory msg = InterchainMsg({
            srcChainID: 1,
            dstChainID: 2,
            srcAddress: btcAddress,
            dstAddress: exocoreAddress,
            token: BTC_ADDR,
            amount: amount,
            nonce: 1,
            txHash: "txHash",
            payload: ""
        });

        bytes memory signature = "signature";
        exocoreBtcGateway.depositThenDelegateTo(msg, operator, signature);
        // Add assertions to validate the deposit and delegation
    }
}
