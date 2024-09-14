// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";

import {ActionAttributes} from "../libraries/ActionAttributes.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {Action} from "../storage/GatewayStorage.sol";

import {Errors} from "../libraries/Errors.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/// @title ClientGatewayLzReceiver
/// @author ExocoreNetwork
/// @notice This contract receives messages over LayerZero from the Exocore Gateway.
/// @dev It is abstract because it does not call the base contract's constructor.
abstract contract ClientGatewayLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {

    using ActionAttributes for Action;

    /// @dev Ensure that the function is called only from this contract.
    modifier onlyCalledFromThis() {
        if (msg.sender != address(this)) {
            revert Errors.ClientGatewayLzReceiverOnlyCalledFromThis();
        }
        _;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    // This function would call other functions inside this contract through low-level-call
    // slither-disable-next-line reentrancy-no-eth
    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        if (_origin.srcEid != EXOCORE_CHAIN_ID) {
            revert Errors.UnexpectedSourceChain(_origin.srcEid);
        }

        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            _handleResponse(payload);
        } else {
            bytes4 selector_ = _whiteListFunctionSelectors[act];
            if (selector_ == bytes4(0)) {
                revert Errors.UnsupportedRequest(act);
            }

            (bool success, bytes memory reason) =
                address(this).call(abi.encodePacked(selector_, abi.encode(payload[1:])));
            if (!success) {
                revert Errors.RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
            }
        }
        emit MessageExecuted(act, _origin.nonce);
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

    /// @dev Called after a response is received from the Exocore Gateway.
    /// @param response The response payload.
    // Though this function makes external calls to contract Vault or ExoCapsule, we just update their state variables
    // and don't make
    // calls to other contracts that do not belong to Exocore.
    // And (success, updatedBalance) would be updated according to response message.
    // slither-disable-next-line reentrancy-no-eth
    function _handleResponse(bytes calldata response) internal {
        (uint64 requestId, Action requestAct, bytes memory cachedRequest) = _getCachedRequestForResponse(response);

        bool success = false;
        uint256 updatedBalance;

        if (requestAct.expectBasicResponse()) {
            success = _decodeBasicResponse(response);
        } else if (requestAct.expectBalanceResponse()) {
            (address token, address staker,, uint256 amount) = _decodeCachedRequest(requestAct, cachedRequest);
            (success, updatedBalance) = _decodeBalanceResponse(response);

            if (requestAct.isPrincipalType()) {
                if (success || requestAct.isDeposit()) {
                    _updatePrincipalAssetState(requestAct, token, staker, amount, updatedBalance);
                }
            } else {
                if (success) {
                    IVault vault = _getVault(token);

                    vault.updateRewardBalance(staker, updatedBalance);
                    if (requestAct.isWithdrawal()) {
                        vault.updateWithdrawableBalance(staker, 0, amount);
                    }
                }
            }
        } else {
            revert Errors.UnsupportedResponse(requestAct);
        }

        delete _registeredRequestActions[requestId];
        delete _registeredRequests[requestId];

        emit RequestFinished(requestAct, requestId, success);
    }

    /// @dev Gets the cached request for a response.
    /// @param response The response for which the request is made.
    /// @return RequestId for the response
    /// @return The action for the response
    /// @return The cached request for the response
    function _getCachedRequestForResponse(bytes calldata response)
        internal
        view
        returns (uint64, Action, bytes memory)
    {
        uint64 requestId = uint64(bytes8(response[1:9]));

        bytes memory cachedRequest = _registeredRequests[requestId];
        if (cachedRequest.length == 0) {
            revert Errors.UnexpectedResponse(requestId);
        }
        Action requestAct = _registeredRequestActions[requestId];

        return (requestId, requestAct, cachedRequest);
    }

    /// @dev Decodes the cached request.
    /// @param requestAct The request action
    /// @param cachedRequest The cached request against that action
    /// @return token The address of the token
    /// @return staker The address of the staker
    /// @return operator The operator address, as a bech32 string
    /// @return amount The amount of the operation
    function _decodeCachedRequest(Action requestAct, bytes memory cachedRequest)
        internal
        pure
        returns (address token, address staker, string memory operator, uint256 amount)
    {
        if (requestAct.isAssetOperationRequest()) {
            (token, staker, amount) = abi.decode(cachedRequest, (address, address, uint256));
        } else if (requestAct.isStakingOperationRequest()) {
            (token, staker, operator, amount) = abi.decode(cachedRequest, (address, address, string, uint256));
        } else {
            revert Errors.UnsupportedRequest(requestAct);
        }

        return (token, staker, operator, amount);
    }

    /// @dev Decodes the balance response.
    /// @param response The response to decode.
    /// @return success The success status of the response
    /// @return updatedBalance The updated balance
    function _decodeBalanceResponse(bytes calldata response)
        internal
        pure
        returns (bool success, uint256 updatedBalance)
    {
        success = (uint8(bytes1(response[9])) == 1);
        updatedBalance = uint256(bytes32(response[10:]));

        return (success, updatedBalance);
    }

    /// @dev Decodes the basic response.
    /// @param response The response to decode.
    /// @return success The success status of the response
    function _decodeBasicResponse(bytes calldata response) internal pure returns (bool success) {
        success = (uint8(bytes1(response[9])) == 1);

        return success;
    }

    /// @dev Updates the principal asset state.
    /// @param requestAct The request action
    /// @param token The token address
    /// @param staker The staker address
    /// @param amount The amount of the operation
    /// @param updatedBalance The updated balance
    function _updatePrincipalAssetState(
        Action requestAct,
        address token,
        address staker,
        uint256 amount,
        uint256 updatedBalance
    ) internal {
        if (token == VIRTUAL_NST_ADDRESS) {
            IExoCapsule capsule = _getCapsule(staker);

            capsule.updatePrincipalBalance(updatedBalance);
            if (requestAct.isWithdrawal()) {
                capsule.updateWithdrawableBalance(amount);
            }
        } else {
            IVault vault = _getVault(token);

            vault.updatePrincipalBalance(staker, updatedBalance);
            if (requestAct.isWithdrawal()) {
                vault.updateWithdrawableBalance(staker, amount, 0);
            }
        }
    }

    /// @notice Called after an add-whitelist-token response is received.
    /// @param payload The request payload.
    // Though `_deployVault` would make external call to newly created `Vault` contract and initialize it,
    // `Vault` contract belongs to Exocore and we could make sure its implementation does not have dangerous behavior
    // like reentrancy.
    // slither-disable-next-line reentrancy-no-eth
    function afterReceiveAddWhitelistTokenRequest(bytes calldata payload) public onlyCalledFromThis whenNotPaused {
        _validatePayloadLength(payload, ADD_TOKEN_WHITELIST_REQUEST_LENGTH, Action.REQUEST_ADD_WHITELIST_TOKEN);
        (address token, uint128 tvlLimit) = _decodeTokenUint128(payload);
        isWhitelistedToken[token] = true;
        whitelistTokens.push(token);
        // since tokens cannot be removed from the whitelist, it is not possible for a vault
        // to already exist. however, we should still ensure that a vault is not deployed for
        // restaking native staked eth. in this case, the tvlLimit is ignored.
        if (token != VIRTUAL_NST_ADDRESS) {
            _deployVault(token, uint256(tvlLimit));
        }
        emit WhitelistTokenAdded(token);
    }

    /// @notice Called after a mark-bootstrap response is received.
    /// @dev Since the contract is already bootstrapped (if we are here), there is nothing to do.
    /// @dev Failing this, however, will cause a nonce mismatch resulting in a system halt.
    ///      Hence, we silently ignore this call.
    function afterReceiveMarkBootstrapRequest() public onlyCalledFromThis whenNotPaused {
        emit BootstrappedAlready();
    }

    /// @dev Decodes a token and a uint128 from a payload. If the token isn't whitelisted, it
    /// reverts.
    /// @param payload The payload to decode.
    /// @return token The token address
    /// @return value The uint128 value
    function _decodeTokenUint128(bytes calldata payload) internal view returns (address, uint128) {
        bytes32 tokenAsBytes32 = bytes32(payload[:32]);
        address token = address(bytes20(tokenAsBytes32));
        if (token == address(0)) {
            // cannot happen since the precompiles check for this
            revert Errors.ZeroAddress();
        }
        if (isWhitelistedToken[token]) {
            // we are receiving a request to whitelist a token that is already whitelisted
            revert Errors.ClientChainGatewayAlreadyWhitelisted(token);
        }
        uint128 value = uint128(bytes16(payload[32:]));
        return (token, value);
    }

}
