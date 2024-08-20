// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "src/core/ExocoreBtcGateway.sol";
import "src/interfaces/precompiles/IAssets.sol";
import "src/interfaces/precompiles/IClaimReward.sol";
import "src/interfaces/precompiles/IDelegation.sol";
import "src/libraries/SignatureVerifier.sol";
import "src/storage/ExocoreBtcGatewayStorage.sol";

import "forge-std/Test.sol";

contract ExocoreBtcGatewayTest is ExocoreBtcGatewayStorage, Test {

    ExocoreBtcGateway internal exocoreBtcGateway;

    uint32 internal exocoreChainId = 2;
    uint32 internal clientBtcChainId = 111;

    address internal validator = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
    address internal btcToken = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    address internal delegatorAddr = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    bytes internal BTC_TOKEN = abi.encodePacked(bytes32(bytes20(btcToken)));

    using stdStorage for StdStorage;

    // Mock contracts
    IDelegation internal mockDelegation;
    IAssets internal mockAssets;
    IClaimReward internal mockClaimReward;

    function setUp() public {
        // Deploy mock contracts
        _bindPrecompileMocks();

        // Deploy the main contract
        exocoreBtcGateway = new ExocoreBtcGateway();

        // Whitelist the btcToken
        // Calculate the storage slot for the mapping
        bytes32 whitelistedSlot = bytes32(
            stdstore.target(address(exocoreBtcGateway)).sig("isWhitelistedToken(address)").with_key(btcToken).find()
        );

        // Set the storage value to true (1)
        vm.store(address(exocoreBtcGateway), whitelistedSlot, bytes32(uint256(1)));
    }

    function _bindPrecompileMocks() internal {
        // bind precompile mock contracts code to constant precompile address so that local simulation could pass
        bytes memory AssetsMockCode = vm.getDeployedCode("AssetsMock.sol");
        vm.etch(ASSETS_PRECOMPILE_ADDRESS, AssetsMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }

    /**
     * @notice Test the depositTo function with the first InterchainMsg.
     */
    function testDepositToWithFirstMessage() public {
        assertTrue(exocoreBtcGateway.isWhitelistedToken(btcToken));

        bytes memory btcAddress = _stringToBytes("tb1pdwf5ar0kxr2sdhxw28wqhjwzynzlkdrqlgx8ju3sr02hkldqmlfspm0mmh");
        bytes memory exocoreAddress = _addressToBytes(delegatorAddr);
        console.logBytes(btcAddress);

        // Get the inboundBytesNonce
        uint256 nonce = exocoreBtcGateway.inboundBytesNonce(clientBtcChainId, btcAddress) + 1;
        assertEq(nonce, 1, "Nonce should be 1");

        // register address.
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        InterchainMsg memory _msg = InterchainMsg({
            srcChainID: clientBtcChainId,
            dstChainID: exocoreChainId,
            srcAddress: btcAddress,
            dstAddress: _stringToBytes("tb1qqytgqkzvg48p700s46n57wfgaf04h7ca5m03qcschaawv9qqw2vsp67ku4"),
            token: btcToken,
            amount: 39_900_000_000_000,
            nonce: 1,
            txTag: _stringToBytes("b2c4366e29da536bd1ca5ac1790ba1d3a5e706a2b5e2674dee2678a669432ffc-3"),
            payload: "0x"
        });

        bytes memory signature =
            hex"aa70b655593f96d19dca3ef0bfc6602b6597a3b6253de2b709b81306a09d46867f857e8a44e64f0c1be6f4ec90a66e28401e007b7efb6fd344164af8316e1f571b";

        // Check if the event is emitted correctly
        vm.expectEmit(true, true, true, true);
        emit DepositCompleted(_msg.txTag, btcToken, exocoreAddress, _msg.amount, 39_900_000_000_000);

        // Simulate the validator calling the depositTo function
        vm.prank(validator);
        exocoreBtcGateway.depositTo(_msg, signature);
    }

    /**
     * @notice Test the depositTo function with the second InterchainMsg.
     */
    function testDepositToWithSecondMessage() public {
        assertTrue(exocoreBtcGateway.isWhitelistedToken(btcToken));
        bytes memory btcAddress = _stringToBytes("tb1p43yswl96qlz9v9m6wtvv9c7s0jv7g6dktwfcuzle6nflyyhrqhpqtdacpy");
        bytes memory exocoreAddress = _addressToBytes(address(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC));

        console.logBytes(btcAddress);

        // Get the inboundBytesNonce
        uint256 nonce = exocoreBtcGateway.inboundBytesNonce(clientBtcChainId, btcAddress) + 1;
        assertEq(nonce, 1, "Nonce should be 1");

        // register address.
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);

        InterchainMsg memory _msg = InterchainMsg({
            srcChainID: clientBtcChainId,
            dstChainID: exocoreChainId,
            srcAddress: btcAddress,
            dstAddress: _stringToBytes("tb1qqytgqkzvg48p700s46n57wfgaf04h7ca5m03qcschaawv9qqw2vsp67ku4"),
            token: btcToken,
            amount: 49_000_000_000_000, // 0.000049 BTC
            nonce: 1,
            txTag: _stringToBytes("102f5578c65f78cda5b1c4b35b58281b66c27a4929bb4f938fd15fa8f2d1c58b-1"),
            payload: "0x"
        });
        // This is a placeholder signature. In a real scenario, you would need to generate a valid signature.
        bytes memory signature =
            hex"4eb94c22acf431262f040dbb99bec5acc6b8288c61d4acbe6a8ba7969ab0cea91613579684c664cd81dd876a385c0c493646267fbbdd58f9408d784e8b8e616d1b";
        // Check if the event is emitted correctly
        vm.expectEmit(true, true, true, true);
        emit DepositCompleted(_msg.txTag, btcToken, exocoreAddress, _msg.amount, 49_000_000_000_000);

        // Simulate the validator calling the depositTo function
        vm.prank(validator);
        exocoreBtcGateway.depositTo(_msg, signature);
    }

    function testEstimateGas() public {
        bytes memory data =
            hex"016322c3000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002e000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001800000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c59900000000000000000000000000000000000000000000000000002449f1539800000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000260000000000000000000000000000000000000000000000000000000000000003e74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d680000000000000000000000000000000000000000000000000000000000000000003e7462317171797467716b7a76673438703730307334366e35377766676166303468376361356d3033716373636861617776397171773276737036376b753400000000000000000000000000000000000000000000000000000000000000000042623263343336366532396461353336626431636135616331373930626131643361356537303661326235653236373464656532363738613636393433326666632d330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002307800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411b599ef9aebf5d2a65c6e8288e1e1d3fbcbe30d891a016110c5dbba48a91037f34c5b1b5cc5903b59a19ae5b58ebd3eb659deaf651b74bf4b50ca5bc22e8f7b11c00000000000000000000000000000000000000000000000000000000000000";

        bytes memory btcAddress = _stringToBytes("tb1pdwf5ar0kxr2sdhxw28wqhjwzynzlkdrqlgx8ju3sr02hkldqmlfspm0mmh");
        bytes memory exocoreAddress = _stringToBytes("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        // register address.
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        // Estimate gas
        vm.prank(validator);
        (bool success, bytes memory returnData) =
            address(0x5FC8d32690cc91D4c39d9d3abcBD16989F875707).call{gas: 1_000_000}(data);
        if (!success) {
            // Decode revert reason
            if (returnData.length > 0) {
                // The call reverted with a reason or a custom error
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert("Call failed without a reason");
            }
        }
    }

    /**
     * @notice Test the delegateTo function
     */
    function testDelegateTo() public {
        bytes memory delegator = _addressToBytes(delegatorAddr);
        bytes memory operator = _stringToBytes("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac");
        uint256 amount = 1_000_000_000; // 10 BTC
        vm.expectEmit(true, true, true, true);
        emit DelegationCompleted(btcToken, delegator, operator, amount);
        vm.prank(validator);
        exocoreBtcGateway.delegateTo(btcToken, delegator, operator, amount);
    }

    /**
     * @notice Test the undelegateFrom function
     */
    function testUndelegateFrom() public {
        bytes memory delegator = _addressToBytes(delegatorAddr);
        bytes memory operator = _stringToBytes("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac");
        uint256 amount = 500_000_000; // 5 BTC

        // Use exocoreBtcGateway's interface to set the initial delegation amount
        vm.prank(validator); // Assume only the validator can call this function
        exocoreBtcGateway.delegateTo(btcToken, delegator, operator, amount);

        vm.expectEmit(true, true, true, true);
        emit UndelegationCompleted(btcToken, delegator, operator, amount);

        vm.prank(validator);
        exocoreBtcGateway.undelegateFrom(btcToken, delegator, operator, amount);

        // Verify that the delegation amount has not changed
        vm.prank(validator);
        (bool success, bytes memory data) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSignature(
                "getDelegateAmount(address,string,uint32,address)",
                delegatorAddr,
                "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac",
                clientBtcChainId,
                btcToken
            )
        );
        require(success, "Low-level call failed");
        uint256 invalidAmount = 0;
        uint256 retrievedAmount = abi.decode(data, (uint256));
        assertEq(retrievedAmount, invalidAmount);
    }
    /**
     * @notice Test the withdrawPrincipal function
     */

    function testWithdrawPrincipal() public {
        testDepositToWithFirstMessage();
        bytes memory withdrawer = _addressToBytes(delegatorAddr);
        uint256 amount = 39_900_000_000_000;
        vm.expectEmit(true, true, true, true);
        emit WithdrawPrincipalCompleted(btcToken, withdrawer, amount, 0);
        vm.prank(validator);
        exocoreBtcGateway.withdrawPrincipal(btcToken, withdrawer, amount);
    }
    /**
     * @notice Test the withdrawReward function
     */

    function testWithdrawReward() public {
        bytes memory withdrawer = _addressToBytes(delegatorAddr);
        uint256 amount = 500; // 1 BTC
        vm.expectEmit(true, true, true, true);
        emit WithdrawRewardCompleted(btcToken, withdrawer, amount, 1234);
        vm.prank(validator);
        exocoreBtcGateway.withdrawReward(btcToken, withdrawer, amount);
    }
    /**
     * @notice Test delegateTo with invalid token
     */

    function testDelegateToInvalidToken() public {
        bytes memory delegator = _addressToBytes(delegatorAddr);
        bytes memory operator = _stringToBytes("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac");
        uint256 amount = 1_000_000_000; // 10 BTC
        address invalidToken = address(0x1111111111111111111111111111111111111111);
        vm.expectRevert("ExocoreBtcGatewayStorage: token is not whitelisted");
        vm.prank(validator);
        exocoreBtcGateway.delegateTo(invalidToken, delegator, operator, amount);
    }
    /**
     * @notice Test undelegateFrom with invalid amount
     */

    function testUndelegateFromInvalidAmount() public {
        bytes memory delegator = _addressToBytes(delegatorAddr);
        bytes memory operator = _stringToBytes("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac");
        uint256 invalidAmount = 0;
        vm.expectRevert("ExocoreBtcGatewayStorage: amount should be greater than zero");
        vm.prank(validator);
        exocoreBtcGateway.undelegateFrom(btcToken, delegator, operator, invalidAmount);
    }
    /**
     * @notice Test withdrawPrincipal when paused
     */

    function testWithdrawPrincipalWhenPaused() public {
        bytes memory withdrawer = _addressToBytes(delegatorAddr);
        uint256 amount = 300_000_000; // 3 BTC
        vm.prank(exocoreBtcGateway.owner());
        exocoreBtcGateway.pause();
        vm.expectRevert("Pausable: paused");
        vm.prank(validator);
        exocoreBtcGateway.withdrawPrincipal(btcToken, withdrawer, amount);
    }

    /**
     * @notice Test depositThenDelegateTo function
     */
    function testDepositThenDelegateTo() public {
        bytes memory btcAddress = _stringToBytes("tb1pdwf5ar0kxr2sdhxw28wqhjwzynzlkdrqlgx8ju3sr02hkldqmlfspm0mmh");
        bytes memory exocoreAddress = _addressToBytes(delegatorAddr);
        // bytes memory exocoreAddress = _stringToBytes("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        bytes memory operator = _stringToBytes("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        // Register address
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        InterchainMsg memory _msg = InterchainMsg({
            srcChainID: clientBtcChainId,
            dstChainID: exocoreChainId,
            srcAddress: btcAddress,
            dstAddress: _stringToBytes("tb1qqytgqkzvg48p700s46n57wfgaf04h7ca5m03qcschaawv9qqw2vsp67ku4"),
            token: btcToken,
            amount: 39_900_000_000_000,
            nonce: 1,
            txTag: _stringToBytes("b2c4366e29da536bd1ca5ac1790ba1d3a5e706a2b5e2674dee2678a669432ffc-3"),
            payload: "0x"
        });
        bytes memory signature =
            hex"aa70b655593f96d19dca3ef0bfc6602b6597a3b6253de2b709b81306a09d46867f857e8a44e64f0c1be6f4ec90a66e28401e007b7efb6fd344164af8316e1f571b";
        vm.expectEmit(true, true, true, true);
        emit DepositAndDelegationCompleted(btcToken, exocoreAddress, operator, _msg.amount, 39_900_000_000_000);
        vm.prank(validator);
        exocoreBtcGateway.depositThenDelegateTo(_msg, operator, signature);
    }
    /**
     * @notice Test registerAddress function
     */

    function testRegisterAddress() public {
        bytes memory btcAddress = _stringToBytes("tb1pdwf5ar0kxr2sdhxw28wqhjwzynzlkdrqlgx8ju3sr02hkldqmlfspm0mmh");
        bytes memory exocoreAddress = _stringToBytes("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        vm.expectEmit(true, true, true, true);
        emit AddressRegistered(btcAddress, exocoreAddress);
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        assertEq(exocoreBtcGateway.btcToExocoreAddress(btcAddress), exocoreAddress);
        assertEq(exocoreBtcGateway.exocoreToBtcAddress(exocoreAddress), btcAddress);
    }
    /**
     * @notice Test registerAddress with already registered addresses
     */

    function testRegisterAddressAlreadyRegistered() public {
        bytes memory btcAddress = _stringToBytes("tb1pdwf5ar0kxr2sdhxw28wqhjwzynzlkdrqlgx8ju3sr02hkldqmlfspm0mmh");
        bytes memory exocoreAddress = _stringToBytes("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
        vm.expectRevert("Depositor address already registered");
        vm.prank(validator);
        exocoreBtcGateway.registerAddress(btcAddress, exocoreAddress);
    }
    /**
     * @notice Test pause and unpause functions
     */

    function testPauseUnpause() public {
        vm.prank(exocoreBtcGateway.owner());
        exocoreBtcGateway.pause();
        assertTrue(exocoreBtcGateway.paused());
        vm.prank(exocoreBtcGateway.owner());
        exocoreBtcGateway.unpause();
        assertFalse(exocoreBtcGateway.paused());
    }
    // Helper function to convert string to bytes

    function _stringToBytes(string memory source) internal pure returns (bytes memory) {
        return abi.encodePacked(source);
    }

    function _addressToBytes(address _addr) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(bytes20(_addr)));
    }

}
