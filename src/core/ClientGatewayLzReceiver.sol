pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/// @title ClientGatewayLzReceiver
/// @author ExocoreNetwork
/// @notice This contract receives messages over LayerZero from the Exocore Gateway.
/// @dev It is abstract because it does not call the base contract's constructor.
abstract contract ClientGatewayLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {

    /// @dev Thrown when the response is unsupported, that is, no hook has been registered for it.
    /// @param act The action that was unsupported.
    error UnsupportedResponse(Action act);

    /// @dev Thrown when the response received is unexpected, that is, the request payload for the id cannot be
    /// retrieved.
    /// @param nonce The nonce of the request.
    error UnexpectedResponse(uint64 nonce);

    /// @dev Thrown when deposit fails on the Exocore end.
    /// @param token The token address.
    /// @param depositor The depositor address.
    error DepositShouldNotFailOnExocore(address token, address depositor);

    /// @dev Thrown when the whitelist tokens length is invalid.
    /// @param expectedLength The expected length of the request payload.
    /// @param actualLength The actual length of the request payload.
    error InvalidAddWhitelistTokensRequest(uint256 expectedLength, uint256 actualLength);

    /// @notice Emitted when withdrawal fails on the Exocore end.
    /// @param token The token address.
    /// @param withdrawer The withdrawer address.
    event WithdrawFailedOnExocore(address indexed token, address indexed withdrawer);

    /// @dev Ensure that the function is called only from this contract.
    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ClientChainLzReceiver: could only be called from this contract itself with low level call"
        );
        _;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    // This function would call other functions inside this contract through low-level-call
    // slither-disable-next-line reentrancy-no-eth
    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        if (_origin.srcEid != EXOCORE_CHAIN_ID) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }

        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            uint64 requestId = uint64(bytes8(payload[1:9]));

            Action requestAct = _registeredRequestActions[requestId];
            bytes4 hookSelector = _registeredResponseHooks[requestAct];
            if (hookSelector == bytes4(0)) {
                revert UnsupportedResponse(act);
            }

            bytes memory requestPayload = _registeredRequests[requestId];
            if (requestPayload.length == 0) {
                revert UnexpectedResponse(requestId);
            }

            (bool success, bytes memory reason) =
                address(this).call(abi.encodePacked(hookSelector, abi.encode(requestPayload, payload[9:])));
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
            }

            delete _registeredRequestActions[requestId];
            delete _registeredRequests[requestId];
        } else {
            bytes4 selector_ = _whiteListFunctionSelectors[act];
            if (selector_ == bytes4(0)) {
                revert UnsupportedRequest(act);
            }

            (bool success, bytes memory reason) =
                address(this).call(abi.encodePacked(selector_, abi.encode(payload[1:])));
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
            }
        }
    }

    /// @inheritdoc OAppReceiverUpgradeable
    function nextNonce(uint32 srcEid, bytes32 sender)
        public
        view
        virtual
        override(OAppReceiverUpgradeable)
        returns (uint64)
    {
        return inboundNonce[srcEid][sender] + 1;
    }

    /// @notice Called after a deposit response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveDepositResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address depositor, uint256 amount) = abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipalBalance = uint256(bytes32(responsePayload[1:]));

        if (!success) {
            revert DepositShouldNotFailOnExocore(token, depositor);
        }

        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(depositor);
            capsule.updatePrincipalBalance(lastlyUpdatedPrincipalBalance);
        } else {
            IVault vault = _getVault(token);
            vault.updatePrincipalBalance(depositor, lastlyUpdatedPrincipalBalance);
        }

        emit DepositResult(success, token, depositor, amount);
    }

    /// @notice Called after a withdraw principal response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveWithdrawPrincipalResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockPrincipalAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipalBalance = uint256(bytes32(responsePayload[1:33]));

        if (!success) {
            emit WithdrawFailedOnExocore(token, withdrawer);
        } else {
            if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
                IExoCapsule capsule = _getCapsule(withdrawer);

                capsule.updatePrincipalBalance(lastlyUpdatedPrincipalBalance);
                capsule.updateWithdrawableBalance(unlockPrincipalAmount);
            } else {
                IVault vault = _getVault(token);

                vault.updatePrincipalBalance(withdrawer, lastlyUpdatedPrincipalBalance);
                vault.updateWithdrawableBalance(withdrawer, unlockPrincipalAmount, 0);
            }

            emit WithdrawPrincipalResult(success, token, withdrawer, unlockPrincipalAmount);
        }
    }

    /// @notice Called after a withdraw reward response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveWithdrawRewardResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockRewardAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedRewardBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = _getVault(token);

            vault.updateRewardBalance(withdrawer, lastlyUpdatedRewardBalance);
            vault.updateWithdrawableBalance(withdrawer, 0, unlockRewardAmount);
        }

        emit WithdrawRewardResult(success, token, withdrawer, unlockRewardAmount);
    }

    /// @notice Called after a delegate response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveDelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address delegator, string memory operator, uint256 amount) =
            abi.decode(requestPayload, (address, address, string, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit DelegateResult(success, delegator, operator, token, amount);
    }

    /// @notice Called after an undelegate response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveUndelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address undelegator, string memory operator, uint256 amount) =
            abi.decode(requestPayload, (address, address, string, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit UndelegateResult(success, undelegator, operator, token, amount);
    }

    /// @notice Called after a deposit-then-delegate response is received.
    /// @param requestPayload The request payload.
    /// @param responsePayload The response payload.
    function afterReceiveDepositThenDelegateToResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address delegator, string memory operator, uint256 amount) =
            abi.decode(requestPayload, (address, address, string, uint256));

        bool delegateSuccess = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipalBalance = uint256(bytes32(responsePayload[1:]));

        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(delegator);
            capsule.updatePrincipalBalance(lastlyUpdatedPrincipalBalance);
        } else {
            IVault vault = _getVault(token);
            vault.updatePrincipalBalance(delegator, lastlyUpdatedPrincipalBalance);
        }

        emit DepositThenDelegateResult(delegateSuccess, delegator, operator, token, amount);
    }

    /// @notice Called after an add-whitelist-tokens response is received.
    /// @param requestPayload The request payload.
    // Though `_deployVault` would make external call to newly created `Vault` contract and initialize it,
    // `Vault` contract belongs to Exocore and we could make sure its implementation does not have dangerous behavior
    // like reentrancy.
    // slither-disable-next-line reentrancy-no-eth
    function afterReceiveAddWhitelistTokensRequest(bytes calldata requestPayload)
        public
        onlyCalledFromThis
        whenNotPaused
    {
        uint8 count = uint8(requestPayload[0]);
        uint256 expectedLength = count * TOKEN_ADDRESS_BYTES_LENGTH + 1;
        if (requestPayload.length != expectedLength) {
            revert InvalidAddWhitelistTokensRequest(expectedLength, requestPayload.length);
        }

        for (uint256 i; i < count; i++) {
            uint256 start = i * TOKEN_ADDRESS_BYTES_LENGTH + 1;
            uint256 end = start + TOKEN_ADDRESS_BYTES_LENGTH;
            address token = address(bytes20(requestPayload[start:end]));

            if (!isWhitelistedToken[token]) {
                isWhitelistedToken[token] = true;
                whitelistTokens.push(token);

                // deploy the corresponding vault if not deployed before
                if (token != VIRTUAL_STAKED_ETH_ADDRESS && address(tokenToVault[token]) == address(0)) {
                    _deployVault(token);
                }

                emit WhitelistTokenAdded(token);
            }
        }
    }

}
