// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IExocoreBtcGateway} from "../interfaces/IExocoreBtcGateway.sol";
import {ASSETS_CONTRACT} from "../interfaces/precompiles/IAssets.sol";
import {CLAIM_REWARD_CONTRACT} from "../interfaces/precompiles/IClaimReward.sol";
import {DELEGATION_CONTRACT} from "../interfaces/precompiles/IDelegation.sol";
import {SignatureVerifier} from "../libraries/SignatureVerifier.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract ExocoreBtcGateway is
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
    bytes internal constant BTC_TOKEN = abi.encodePacked(BTC_ADDR);
    mapping(bytes => TxInfo) public processedBtcTxs;
    mapping(bytes => bytes) public btcToExocoreAddress;
    mapping(bytes => bytes) public exocoreToBtcAddress;

    event DepositCompleted(bytes btcTxHash, bytes token, bytes depositor, uint256 amount, uint256 updatedBalance);
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
    error DepositFailed(bytes btcTxHash);
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

    function pause() external onlyAuthorizedValidator {
        _pause();
    }

    function unpause() external onlyAuthorizedValidator {
        _unpause();
    }

    constructor(uint32 clientChainId) {
        _registerClientChain(clientChainId);
        _disableInitializers();
    }

    function initialize(address payable exocoreValidatorSetAddress_) external initializer {
        if (exocoreValidatorSetAddress_ == address(0)) {
            revert ZeroAddressNotAllowed();
        }

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    // TODO: this registerClientChain should implement in ExocoreGateway.
    // this will removed and register from ExocoreGateway.
    function _registerClientChain(uint32 clientChainId) internal {
        if (clientChainId == 0) {
            revert ZeroAddressNotAllowed();
        }
        if (!ASSETS_CONTRACT.registerClientChain(clientChainId)) {
            revert RegisterClientChainToExocoreFailed(clientChainId);
        }
        CLIENT_CHAIN_ID = clientChainId;
    }

    function registerAddress(bytes calldata btcAddress, bytes calldata exocoreAddress) external {
        require(btcAddress.length > 0 && exocoreAddress.length > 0, "Invalid address");
        btcToExocoreAddress[btcAddress] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = btcAddress;
        emit AddressRegistered(btcAddress, exocoreAddress);
    }

    function _verifySignature(InterchainMsg calldata _msg, bytes memory signature) internal view {
        // InterchainMsg, EIP721 is preferred next step.
        bytes32 digest = keccak256(
            abi.encodePacked(
                _msg.srcChainID,
                _msg.dstChainID,
                _msg.srcAddress,
                _msg.dstAddress,
                _msg.token,
                _msg.amount,
                _msg.nonce,
                _msg.txHash,
                _msg.payload
            )
        ).toEthSignedMessageHash();

        SignatureVerifier.verifyMsgSig(exocoreValidatorSetAddress, digest, signature);
    }

    function _processAndVerify(InterchainMsg calldata _msg, bytes calldata signature)
        internal
        returns (bytes memory btcTxHash, bytes memory btcAddress, bytes memory exocoreAddress)
    {
        btcTxHash = _msg.txHash;
        btcAddress = _msg.srcAddress;

        if (processedBtcTxs[btcTxHash].processed) {
            revert BtcTxAlreadyProcessed();
        }

        // Verify nonce
        _verifyAndUpdateBytesNonce(_msg.srcChainID, btcAddress, _msg.nonce);

        // Verify signature
        _verifySignature(_msg, signature);

        exocoreAddress = btcToExocoreAddress[btcAddress];
        if (exocoreAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }
    }

    // this is called by btc-bridge service and signed offline by exocoreValidatorSetAddress.
    // nonce and signature with corresponding _msg verification.
    // btc trnasaction re-orgnized handleing and error handling.
    function depositTo(InterchainMsg calldata _msg, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(_msg.token)
        isValidAmount(_msg.amount)
        onlyAuthorizedValidator
    {
        (bytes memory btcTxHash, bytes memory btcAddress,) = _processAndVerify(_msg, signature);
        try ASSETS_CONTRACT.depositTo(0, BTC_TOKEN, btcAddress, _msg.amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                revert DepositFailed(btcTxHash);
            }
            processedBtcTxs[btcTxHash] = TxInfo(true, block.timestamp);
            emit DepositCompleted(btcTxHash, BTC_TOKEN, btcAddress, _msg.amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed(btcTxHash);
        }
    }

    // this is user interface called by btc-restaker with exochain address.
    // nonce verification.
    function delegateTo(address token, bytes calldata delegator, bytes calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        _nextNonce(CLIENT_CHAIN_ID, delegator);
        try DELEGATION_CONTRACT.delegateTo(CLIENT_CHAIN_ID, BTC_TOKEN, delegator, operator, amount) returns (
            bool success
        ) {
            if (!success) {
                revert DelegationFailed();
            }
            emit DelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert DelegationFailed();
        }
    }

    // this is user interface called by btc-restaker with exochain address.
    // nonce verification.
    function undelegateFrom(address token, bytes calldata delegator, bytes calldata operator, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        _nextNonce(CLIENT_CHAIN_ID, delegator);
        try DELEGATION_CONTRACT.undelegateFrom(CLIENT_CHAIN_ID, BTC_TOKEN, delegator, operator, amount) returns (
            bool success
        ) {
            if (!success) {
                revert UndelegationFailed();
            }
            emit UndelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert UndelegationFailed();
        }
    }

    // this is user interface called by btc-restaker with exochain address.
    // nonce verification.
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

    // this is user interface called by btc-restaker with exochain address.
    // nonce verification.
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

    // TODO: this is user interface called by btc-restaker with exochain address.
    // this progress is able to integrate with depositTo function.
    function depositThenDelegateTo(InterchainMsg calldata _msg, bytes calldata operator, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
        isTokenWhitelisted(BTC_ADDR)
        isValidAmount(_msg.amount)
        onlyAuthorizedValidator
    {
        (bytes memory btcTxHash, bytes memory btcAddress,) = _processAndVerify(_msg, signature);
        _depositToAssetContract(CLIENT_CHAIN_ID, BTC_TOKEN, btcAddress, _msg.amount, btcTxHash, operator);
    }

    function _depositToAssetContract(
        uint32 clientChainId,
        bytes memory btcToken,
        bytes memory btcAddress,
        uint256 amount,
        bytes memory btcTxHash,
        bytes memory operator
    ) internal {
        try ASSETS_CONTRACT.depositTo(clientChainId, btcToken, btcAddress, amount) returns (
            bool depositSuccess, uint256 updatedBalance
        ) {
            if (!depositSuccess) {
                revert DepositFailed(btcTxHash);
            }
            processedBtcTxs[btcTxHash] = TxInfo(true, block.timestamp);
            _delegateToDelegationContract(clientChainId, btcToken, btcAddress, operator, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed(btcTxHash);
        }
    }

    function _delegateToDelegationContract(
        uint32 clientChainId,
        bytes memory btcToken,
        bytes memory btcAddress,
        bytes memory operator,
        uint256 amount,
        uint256 updatedBalance
    ) internal {
        try DELEGATION_CONTRACT.delegateTo(clientChainId, btcToken, btcAddress, operator, amount) returns (
            bool delegateSuccess
        ) {
            if (!delegateSuccess) {
                revert DelegationFailed();
            }
            emit DepositAndDelegationCompleted(BTC_ADDR, btcAddress, operator, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert DelegationFailed();
        }
    }

    function getBtcAddress(bytes calldata exocoreAddress) external view returns (bytes memory) {
        return exocoreToBtcAddress[exocoreAddress];
    }

    function getCurrentNonce(uint32 srcChainId, string calldata btcAddress) external view returns (uint64) {
        bytes memory bytesBtcAddr = _stringToBytes(btcAddress);
        return inboundBytesNonce[srcChainId][bytesBtcAddr];
    }

    function _addressToBytes(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(addr);
    }

    // this srcAddress is exocorechain address, it need convert to btc address.
    function _nextNonce(uint32 srcChainId, bytes calldata srcAddress) internal returns (uint64) {
        bytes memory btcAddress = exocoreToBtcAddress[srcAddress];
        return inboundBytesNonce[srcChainId][btcAddress]++;
    }

    // This function needs to be implemented
    function _isAuthorizedValidator(address validator) internal view returns (bool) {
        // Implementation depends on how you determine if a validator is authorized
        // For example, you might check against a list of authorized validators
        // or query another contract
        return validator == exocoreValidatorSetAddress;
    }

    function _stringToBytes(string memory source) internal pure returns (bytes memory) {
        return abi.encodePacked(source);
    }

}
