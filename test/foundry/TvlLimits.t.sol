pragma solidity ^0.8.19;

import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";

import {IExoCapsule} from "../../src/interfaces/IExoCapsule.sol";
import {ILSTRestakingController} from "../../src/interfaces/ILSTRestakingController.sol";

import "../../src/storage/GatewayStorage.sol";
import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract TvlLimitsTest is ExocoreDeployer {

    function setUp() public virtual override {
        super.setUp();
        test_AddWhitelistTokens();
    }

    using AddressCast for address;

    // a decrease in tvl limit is always permitted
    function test_DecreaseTvlLimit() public {
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(address(vault) != address(0));
        uint256 tvlLimit = vault.getTvlLimit() / 2; // halve the TVL limit
        vm.prank(exocoreValidatorSet.addr);
        clientGateway.updateTvlLimit(address(restakeToken), tvlLimit);
        assertTrue(vault.getTvlLimit() == tvlLimit);
    }

    // a decrease in tvl limit does not require LZ fee
    function test_DecreaseTvlLimit_FailWithValue() public {
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(address(vault) != address(0));
        uint256 tvlLimit = vault.getTvlLimit() / 2; // halve the TVL limit
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.NonZeroValue.selector);
        clientGateway.updateTvlLimit{value: 5}(address(restakeToken), tvlLimit);
    }

    // for a token that is not whitelisted, nothing should happen
    function test07_UpdateTvlLimits_NotWhitelisted() public {
        address addr = address(0xa);
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenNotWhitelisted.selector, addr));
        clientGateway.updateTvlLimit(addr, 500);
        vm.stopPrank();
    }

    // native restaking does not have a TVL limit
    function test07_UpdateTvlLimits_NativeEth() public {
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.NoTvlLimitForNativeRestaking.selector);
        clientGateway.updateTvlLimit(VIRTUAL_STAKED_ETH_ADDRESS, 500);
        vm.stopPrank();
    }

    // whitelist tokens should be added before updating tvl limits
    function test08_AddWhitelistTokens_NotPermitted() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(restakeToken);
        uint256[] memory tvlLimits = new uint256[](1);
        tvlLimits[0] = 500;
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.ClientChainGatewayTokenAdditionViaExocore.selector);
        clientGateway.addWhitelistTokens(tokens, tvlLimits);
    }

    // helper function to increase the tvl limit
    function _increaseTvlLimitOnClientChain(uint256 proposedTvlLimitFactor)
        internal
        returns (uint256, bytes32, bytes memory)
    {
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(address(vault) != address(0));
        uint256 tvlLimit = vault.getTvlLimit();
        uint256 proposedTvlLimit = tvlLimit * proposedTvlLimitFactor;
        vm.startPrank(exocoreValidatorSet.addr);
        bytes memory payload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_VALIDATE_LIMITS,
            abi.encodePacked(bytes32(bytes20(address(restakeToken))), proposedTvlLimit)
        );
        uint256 nativeFee = clientGateway.quote(payload);
        bytes32 requestId = generateUID(outboundNonces[clientChainId], true);
        vm.expectEmit(address(clientGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_VALIDATE_LIMITS, requestId, outboundNonces[clientChainId]++, nativeFee
        );
        clientGateway.updateTvlLimit{value: nativeFee}(address(restakeToken), proposedTvlLimit);
        return (tvlLimit, requestId, payload);
    }

    function _handleTvlLimitIncreaseOnExocore(bool expect, bytes32 requestId, bytes memory requestPayload)
        internal
        returns (bytes32, bytes memory)
    {
        // take this message to Exocore and obtain the response, which should be true
        bytes memory responsePayload =
            abi.encodePacked(GatewayStorage.Action.RESPOND, abi.encodePacked(outboundNonces[clientChainId] - 1, expect));
        bytes32 responseId = generateUID(outboundNonces[exocoreChainId], false);
        // fund the gateway to respond
        deal(address(exocoreGateway), 1e22);
        uint256 nativeFee = exocoreGateway.quote(clientChainId, responsePayload);
        vm.expectEmit(address(exocoreLzEndpoint));
        emit NewPacket(
            clientChainId,
            address(exocoreGateway),
            address(clientGateway).toBytes32(),
            outboundNonces[exocoreChainId],
            responsePayload
        );
        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, outboundNonces[exocoreChainId]++, nativeFee);
        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(GatewayStorage.Action.REQUEST_VALIDATE_LIMITS, inboundNonces[exocoreChainId]++);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
            address(exocoreGateway),
            requestId,
            requestPayload,
            bytes("")
        );
        return (responseId, responsePayload);
    }

    function _handleTvlLimitResponseOnClientChain(bool success, bytes32 responseId, bytes memory responsePayload)
        internal
    {
        vm.expectEmit(address(clientGateway));
        emit RequestFinished(
            GatewayStorage.Action.REQUEST_VALIDATE_LIMITS,
            outboundNonces[clientChainId] - 1, // request id
            success
        );
        vm.expectEmit(address(clientGateway));
        emit MessageExecuted(GatewayStorage.Action.RESPOND, inboundNonces[clientChainId]++);

        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), inboundNonces[clientChainId] - 1),
            address(clientGateway),
            responseId,
            responsePayload,
            bytes("")
        );
        vm.stopPrank();
    }

    function _testTvlLimitIncreaseE2E(uint256 limitFactor, bool success) internal {
        (uint256 prevLimit, bytes32 requestId, bytes memory requestPayload) =
            _increaseTvlLimitOnClientChain(limitFactor);
        (bytes32 responseId, bytes memory responsePayload) =
            _handleTvlLimitIncreaseOnExocore(success, requestId, requestPayload);
        _handleTvlLimitResponseOnClientChain(success, responseId, responsePayload);
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(vault.getTvlLimit() == prevLimit * (success ? limitFactor : uint256(1)));
    }

    function test_IncreaseTvlLimit() public {
        _testTvlLimitIncreaseE2E(20, true);
    }

    function test_IncreaseTvlLimit_TooHigh() public {
        _testTvlLimitIncreaseE2E(21, false);
    }

    function test_IncreaseTvlLimit_SupplyDecrease() public {
        uint256 limitFactor = 19;
        (uint256 prevLimit, bytes32 requestId, bytes memory requestPayload) =
            _increaseTvlLimitOnClientChain(limitFactor);
        bool success = false;
        _decreaseTotalSupplyOnExocore(restakeToken.totalSupply() - 1);
        (bytes32 responseId, bytes memory responsePayload) =
            _handleTvlLimitIncreaseOnExocore(success, requestId, requestPayload);
        _handleTvlLimitResponseOnClientChain(success, responseId, responsePayload);
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(vault.getTvlLimit() == prevLimit * (success ? limitFactor : uint256(1)));
    }

    function test_IncreaseTotalSupply() public {
        // always permitted
        uint256 newSupply = restakeToken.totalSupply() + 1;
        vm.prank(exocoreValidatorSet.addr);
        exocoreGateway.updateWhitelistToken(clientChainId, bytes32(bytes20(address(restakeToken))), newSupply, "");
    }

    function _decreaseTotalSupplyOnExocore(uint256 newSupply) internal returns (bytes32, bytes memory) {
        vm.startPrank(exocoreValidatorSet.addr);
        bytes memory payload = abi.encodePacked(
            GatewayStorage.Action.REQUEST_VALIDATE_LIMITS,
            abi.encodePacked(bytes32(bytes20(address(restakeToken))), newSupply)
        );
        uint256 nativeFee = exocoreGateway.quote(clientChainId, payload);
        bytes32 requestId = generateUID(outboundNonces[exocoreChainId], false);
        vm.expectEmit(address(exocoreGateway));
        emit MessageSent(
            GatewayStorage.Action.REQUEST_VALIDATE_LIMITS, requestId, outboundNonces[exocoreChainId]++, nativeFee
        );
        exocoreGateway.updateWhitelistToken{value: nativeFee}(
            clientChainId, bytes32(bytes20(address(restakeToken))), newSupply, ""
        );
        return (requestId, payload);
    }

    function _handleTotalSupplyDecreaseOnClientChain(bool expect, bytes32 requestId, bytes memory requestPayload)
        internal
        returns (bytes32, bytes memory)
    {
        bytes memory responsePayload = abi.encodePacked(
            GatewayStorage.Action.RESPOND, abi.encodePacked(outboundNonces[exocoreChainId] - 1, expect)
        );
        bytes32 responseId = generateUID(outboundNonces[clientChainId], true);
        deal(address(clientGateway), 1e22);
        uint256 nativeFee = clientGateway.quote(responsePayload);
        vm.expectEmit(address(clientGateway));
        emit MessageSent(GatewayStorage.Action.RESPOND, responseId, outboundNonces[clientChainId]++, nativeFee);
        vm.expectEmit(address(clientGateway));
        emit MessageExecuted(GatewayStorage.Action.REQUEST_VALIDATE_LIMITS, inboundNonces[clientChainId]++);
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, address(exocoreGateway).toBytes32(), inboundNonces[clientChainId] - 1),
            address(clientGateway),
            requestId,
            requestPayload,
            bytes("")
        );
        return (responseId, responsePayload);
    }

    function _handleSupplyResponseOnExocore(bool success, bytes32 responseId, bytes memory responsePayload) internal {
        vm.expectEmit(address(exocoreGateway));
        emit MessageExecuted(GatewayStorage.Action.RESPOND, inboundNonces[exocoreChainId]++);
        exocoreLzEndpoint.lzReceive(
            Origin(clientChainId, address(clientGateway).toBytes32(), inboundNonces[exocoreChainId] - 1),
            address(exocoreGateway),
            responseId,
            responsePayload,
            bytes("")
        );
    }

    function test_DecreaseTotalSupply() public {
        bytes32 tokenAddr = bytes32(bytes20(address(restakeToken)));
        (bool supplied, uint256 prevSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied);
        uint256 newSupply = prevSupply - 1;
        bool expect = true;
        (bytes32 requestId, bytes memory requestPayload) = _decreaseTotalSupplyOnExocore(newSupply);
        (bytes32 responseId, bytes memory responsePayload) =
            _handleTotalSupplyDecreaseOnClientChain(expect, requestId, requestPayload);
        _handleSupplyResponseOnExocore(expect, responseId, responsePayload);
        (bool supplied2, uint256 gotSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied2);
        assertTrue(newSupply == gotSupply);
    }

    function test_DecreaseTotalSupply_TooLow() public {
        bytes32 tokenAddr = bytes32(bytes20(address(restakeToken)));
        (bool supplied, uint256 prevSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied);
        uint256 newSupply = prevSupply / 500;
        bool expect = false;
        (bytes32 requestId, bytes memory requestPayload) = _decreaseTotalSupplyOnExocore(newSupply);
        (bytes32 responseId, bytes memory responsePayload) =
            _handleTotalSupplyDecreaseOnClientChain(expect, requestId, requestPayload);
        _handleSupplyResponseOnExocore(expect, responseId, responsePayload);
        (bool supplied2, uint256 gotSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied2);
        assertTrue(prevSupply == gotSupply);
    }

    function test_DecreaseTotalSupply_TvlLimitIncrease() public {
        _increaseTvlLimitOnClientChain(19);
        bytes32 tokenAddr = bytes32(bytes20(address(restakeToken)));
        (bool supplied, uint256 prevSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied);
        uint256 newSupply = prevSupply - 1;
        bool expect = false;
        (bytes32 requestId, bytes memory requestPayload) = _decreaseTotalSupplyOnExocore(newSupply);
        (bytes32 responseId, bytes memory responsePayload) =
            _handleTotalSupplyDecreaseOnClientChain(expect, requestId, requestPayload);
        _handleSupplyResponseOnExocore(expect, responseId, responsePayload);
        (bool supplied2, uint256 gotSupply) = exocoreGateway.getTotalSupply(clientChainId, tokenAddr);
        assertTrue(supplied2);
        assertTrue(prevSupply == gotSupply);
    }

}
