// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "forge-std/console.sol";
import {IExocoreBtcGateway} from "src/interfaces/IExocoreBtcGateway.sol";
import {ASSETS_CONTRACT} from "src/interfaces/precompiles/IAssets.sol";
import {CLAIM_REWARD_CONTRACT} from "src/interfaces/precompiles/IClaimReward.sol";
import {DELEGATION_CONTRACT} from "src/interfaces/precompiles/IDelegation.sol";
import {SignatureVerifier} from "src/libraries/SignatureVerifier.sol";
import {GatewayStorage} from "src/storage/GatewayStorage.sol";

contract ExocoreBtcGatewayMock is
    IExocoreBtcGateway,
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    GatewayStorage
{

    using MessageHashUtils for bytes32;

    uint32 internal CLIENT_CHAIN_ID;
    address internal constant BTC_ADDR = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    bytes internal constant BTC_TOKEN = abi.encodePacked(bytes12(0), BTC_ADDR);
    mapping(bytes => TxInfo) public processedBtcTxs;
    mapping(bytes => bytes) public btcToExocoreAddress;
    mapping(bytes => bytes) public exocoreToBtcAddress;

    event DepositCompleted(bytes btcTxTag, bytes token, bytes depositor, uint256 amount, uint256 updatedBalance);
    event WithdrawPrincipalCompleted(address token, bytes withdrawer, uint256 amount, uint256 updatedBalance);
    event WithdrawRewardCompleted(address token, bytes withdrawer, uint256 amount, uint256 updatedBalance);
    event DelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);
    event UndelegationCompleted(address token, bytes delegator, bytes operator, uint256 amount);
    event DepositAndDelegationCompleted(
        address token, bytes depositor, bytes operator, uint256 amount, uint256 updatedBalance
    );
    event AddressRegistered(bytes btcAddress, bytes exocoreAddress);
    event ExocorePrecompileError(address precompileAddress);

    error UnauthorizedValidator();
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);
    error ZeroAddressNotAllowed();
    error BtcTxAlreadyProcessed();
    error BtcAddressNotRegistered();
    error DepositFailed(bytes btcTxTag);
    error WithdrawPrincipalFailed();
    error WithdrawRewardFailed();
    error DelegationFailed();
    error UndelegationFailed();
    error EtherTransferFailed();

    modifier onlyAuthorizedValidator() {
        if (!_isAuthorizedValidator(msg.sender)) {
            revert UnauthorizedValidator();
        }
        _;
    }

    constructor(address exocoreValidatorSetAddress_) {
        exocoreValidatorSetAddress = payable(exocoreValidatorSetAddress_);
        isWhitelistedToken[BTC_ADDR] = true;
    }

    function setWhitelistedToken(address token, bool whitelisted) public onlyOwner {
        isWhitelistedToken[token] = whitelisted;
    }

    /**
     * @notice Registers a BTC address with an Exocore address.
     * @param btcAddress The BTC address to register.
     * @param exocoreAddress The corresponding Exocore address.
     */
    function registerAddress(bytes calldata btcAddress, bytes calldata exocoreAddress)
        external
        onlyAuthorizedValidator
    {
        require(btcAddress.length > 0 && exocoreAddress.length > 0, "Invalid address");
        btcToExocoreAddress[btcAddress] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = btcAddress;
        emit AddressRegistered(btcAddress, exocoreAddress);
    }

    /**
     * @notice Verifies the signature of an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     */
    function _verifySignature(InterchainMsg calldata _msg, bytes memory signature) internal view {
        // InterchainMsg, EIP721 is preferred next step.
        bytes memory encodeMsg = abi.encode(
            _msg.srcChainID,
            _msg.dstChainID,
            _msg.srcAddress,
            _msg.dstAddress,
            _msg.token,
            _msg.amount,
            _msg.nonce,
            _msg.txTag,
            _msg.payload
        );

        console.logBytes(encodeMsg);

        bytes32 messageHash = keccak256(encodeMsg);
        bytes32 digest = messageHash.toEthSignedMessageHash();

        console.logBytes32(messageHash);

        SignatureVerifier.verifyMsgSig(exocoreValidatorSetAddress, digest, signature);
    }

    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory bytesArray = new bytes(32);
        for (uint256 i; i < 32; i++) {
            bytesArray[i] = _bytes32[i];
        }
        return string(bytesArray);
    }

    /**
     * @notice Processes and verifies an interchain message.
     * @param _msg The interchain message.
     * @param signature The signature to verify.
     * @return btcTxTag The lowercase of BTC txid-vout.
     * @return btcAddress The BTC address.
     * @return exocoreAddress The Exocore address.
     */
    function _processAndVerify(InterchainMsg calldata _msg, bytes calldata signature)
        internal
        returns (bytes memory btcTxTag, bytes memory btcAddress, bytes memory exocoreAddress)
    {
        btcTxTag = _msg.txTag;
        btcAddress = _msg.srcAddress;

        if (processedBtcTxs[btcTxTag].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // Verify nonce
        _verifyAndUpdateBytesNonce(_msg.srcChainID, btcAddress, _msg.nonce);

        // Verify signature
        _verifySignature(_msg, signature);

        console.log("verify sig done, nonce: ", _msg.nonce);
        exocoreAddress = btcToExocoreAddress[btcAddress];
        if (exocoreAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }
        console.log("verify addr done");
    }

    /**
     * @notice Deposits BTC to the Exocore system.
     * @param _msg The interchain message containing the deposit details.
     * @param signature The signature to verify.
     */
    function depositTo(InterchainMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(_msg.token)
        isValidAmount(_msg.amount)
        onlyAuthorizedValidator
    {
        (bytes memory btcTxTag, bytes memory btcAddress,) = _processAndVerify(_msg, signature);
        console.log("ASSETS_CONTRACT:", address(ASSETS_CONTRACT));
        try ASSETS_CONTRACT.depositTo(_msg.srcChainID, BTC_TOKEN, btcAddress, _msg.amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                console.log("depositTo failed");
                revert DepositFailed(btcTxTag);
            }
            console.log("depositTo success");
            processedBtcTxs[btcTxTag] = TxInfo(true, block.timestamp);
            emit DepositCompleted(btcTxTag, BTC_TOKEN, btcAddress, _msg.amount, updatedBalance);
        } catch {
            console.log("depositTo Error");
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed(btcTxTag);
        }
    }

    /**
     * @notice Withdraws the principal BTC.
     * @param token The token address.
     * @param withdrawer The withdrawer's address.
     * @param amount The amount to withdraw.
     */
    function withdrawPrincipal(address token, bytes calldata withdrawer, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        _nextNonce(CLIENT_CHAIN_ID, withdrawer);
        try ASSETS_CONTRACT.withdrawPrincipal(0, BTC_TOKEN, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                revert WithdrawPrincipalFailed();
            }
            emit WithdrawPrincipalCompleted(token, withdrawer, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert WithdrawPrincipalFailed();
        }
    }

    /**
     * @notice Withdraws the reward BTC.
     * @param token The token address.
     * @param withdrawer The withdrawer's address.
     * @param amount The amount to withdraw.
     */
    function withdrawReward(address token, bytes calldata withdrawer, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        _nextNonce(CLIENT_CHAIN_ID, withdrawer);
        try CLAIM_REWARD_CONTRACT.claimReward(CLIENT_CHAIN_ID, BTC_TOKEN, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                revert WithdrawRewardFailed();
            }
            emit WithdrawRewardCompleted(token, withdrawer, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(CLAIM_REWARD_CONTRACT));
            revert WithdrawRewardFailed();
        }
    }

    /**
     * @notice Gets the BTC address corresponding to an Exocore address.
     * @param exocoreAddress The Exocore address.
     * @return The corresponding BTC address.
     */
    function getBtcAddress(bytes calldata exocoreAddress) external view returns (bytes memory) {
        return exocoreToBtcAddress[exocoreAddress];
    }

    /**
     * @notice Gets the current nonce for a given BTC address.
     * @param srcChainId The source chain ID.
     * @param btcAddress The BTC address as a string.
     * @return The current nonce.
     */
    function getCurrentNonce(uint32 srcChainId, string calldata btcAddress) external view returns (uint64) {
        bytes memory bytesBtcAddr = _stringToBytes(btcAddress);
        return inboundBytesNonce[srcChainId][bytesBtcAddr];
    }

    /**
     * @notice Converts an address to bytes.
     * @param addr The address to convert.
     * @return The address as bytes.
     */
    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(addr);
    }

    /**
     * @notice Increments and gets the next nonce for a given source address.
     * @param srcChainId The source chain ID.
     * @param srcAddress The source address.
     * @return The next nonce.
     */
    function _nextNonce(uint32 srcChainId, bytes calldata srcAddress) internal returns (uint64) {
        bytes memory btcAddress = exocoreToBtcAddress[srcAddress];
        return inboundBytesNonce[srcChainId][btcAddress]++;
    }

    /**
     * @notice Checks if a validator is authorized.
     * @param validator The validator address.
     * @return True if the validator is authorized, false otherwise.
     */
    function _isAuthorizedValidator(address validator) internal view returns (bool) {
        // Implementation depends on how you determine if a validator is authorized
        // For example, you might check against a list of authorized validators
        // or query another contract
        return validator == exocoreValidatorSetAddress;
    }

    /**
     * @notice Converts a string to bytes.
     * @param source The string to convert.
     * @return The string as bytes.
     */
    function _stringToBytes(string memory source) internal pure returns (bytes memory) {
        return abi.encodePacked(source);
    }

}
