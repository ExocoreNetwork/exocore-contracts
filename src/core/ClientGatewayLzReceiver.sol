pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

abstract contract ClientGatewayLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {

    error UnsupportedResponse(Action act);
    error UnexpectedResponse(uint64 nonce);
    error DepositShouldNotFailOnExocore(address token, address depositor);
    error InvalidAddWhitelistTokensRequest(uint256 expectedLength, uint256 actualLength);

    // Events
    event WithdrawFailedOnExocore(address indexed token, address indexed withdrawer);

    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ClientChainLzReceiver: could only be called from this contract itself with low level call"
        );
        _;
    }

    // This function would call other functions inside this contract through low-level-call
    // slither-disable-next-line reentrancy-no-eth
    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        if (_origin.srcEid != EXOCORE_CHAIN_ID) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }

        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            _handleResponse(payload);
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

    function nextNonce(uint32 srcEid, bytes32 sender)
        public
        view
        virtual
        override(OAppReceiverUpgradeable)
        returns (uint64)
    {
        return inboundNonce[srcEid][sender] + 1;
    }

    // Though this function makes external calls to contract Vault or ExoCapsule, we just update their state variables
    // and don't make
    // calls to other contracts that do not belong to Exocore.
    // And (success, updatedBalance) would be updated according to response message.
    // slither-disable-next-line reentrancy-no-eth
    function _handleResponse(bytes calldata response) internal {
        (uint64 requestId, Action requestAct, bytes memory cachedRequest) = _getCachedRequestForResponse(response);

        bool success = false;
        uint256 updatedBalance;

        if (_expectBasicResponse(requestAct)) {
            success = _decodeBasicResponse(response);
        } else if (_expectBalanceResponse(requestAct)) {
            (address token, address staker,, uint256 amount) = _decodeCachedRequest(requestAct, cachedRequest);
            (success, updatedBalance) = _decodeBalanceResponse(response);

            if (_isPrincipalType(requestAct)) {
                // we assume deposit request must always be successful, thus we should always update balance for deposit
                // request
                // Notice: Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO is a special operation that is not atomic, since
                // deposit should always be successful while delegate could fail for some cases
                if (success || _isDeposit(requestAct)) {
                    _updatePrincipalAssetState(requestAct, token, staker, amount, updatedBalance);
                }
            } else {
                // otherwise this is an operation aimed at reward since Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE is
                // the only asset operation request that deals with reward instead of principal
                if (success) {
                    IVault vault = _getVault(token);

                    vault.updateRewardBalance(staker, updatedBalance);
                    if (_isWithdrawal(requestAct)) {
                        vault.updateWithdrawableBalance(staker, 0, amount);
                    }
                }
            }
        } else {
            revert UnsupportedResponse(requestAct);
        }

        delete _registeredRequestActions[requestId];
        delete _registeredRequests[requestId];

        emit RequestFinished(requestAct, requestId, success);
    }

    function _getCachedRequestForResponse(bytes calldata response) internal returns (uint64, Action, bytes memory) {
        uint64 requestId = uint64(bytes8(response[1:9]));

        bytes memory cachedRequest = _registeredRequests[requestId];
        if (cachedRequest.length == 0) {
            revert UnexpectedResponse(requestId);
        }
        Action requestAct = _registeredRequestActions[requestId];

        return (requestId, requestAct, cachedRequest);
    }

    function _isAssetOperationRequest(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DEPOSIT || action == Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
            || action == Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE;
    }

    function _isStakingOperationRequest(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DELEGATE_TO || action == Action.REQUEST_UNDELEGATE_FROM
            || action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO;
    }

    // Basic response only includes reqeust execution status, no other informations like balance update
    // and it is typically the response of a staking only operations.
    function _expectBasicResponse(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DELEGATE_TO || action == Action.REQUEST_UNDELEGATE_FROM;
    }

    // Balance response includes not only request execution status, but also the balance update informations,
    // so it is typically the response of an asset operation.
    function _expectBalanceResponse(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DEPOSIT || action == Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
            || action == Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE || action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO;
    }

    function _isPrincipalType(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DEPOSIT || action == Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
            || action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO;
    }

    function _isWithdrawal(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_WITHDRAW_PRINCIPAL_FROM_EXOCORE
            || action == Action.REQUEST_WITHDRAW_REWARD_FROM_EXOCORE;
    }

    function _isDeposit(Action action) internal pure returns (bool) {
        return action == Action.REQUEST_DEPOSIT || action == Action.REQUEST_DEPOSIT_THEN_DELEGATE_TO;
    }

    function _decodeCachedRequest(Action requestAct, bytes memory cachedRequest)
        internal
        pure
        returns (address token, address staker, string memory operator, uint256 amount)
    {
        if (_isAssetOperationRequest(requestAct)) {
            (token, staker, amount) = abi.decode(cachedRequest, (address, address, uint256));
        } else if (_isStakingOperationRequest(requestAct)) {
            (token, staker, operator, amount) = abi.decode(cachedRequest, (address, address, string, uint256));
        } else {
            revert UnsupportedRequest(requestAct);
        }

        return (token, staker, operator, amount);
    }

    function _decodeBalanceResponse(bytes calldata response)
        internal
        pure
        returns (bool success, uint256 updatedBalance)
    {
        success = (uint8(bytes1(response[9])) == 1);
        updatedBalance = uint256(bytes32(response[10:]));

        return (success, updatedBalance);
    }

    function _decodeBasicResponse(bytes calldata response) internal pure returns (bool success) {
        success = (uint8(bytes1(response[9])) == 1);

        return success;
    }

    function _updatePrincipalAssetState(
        Action requestAct,
        address token,
        address staker,
        uint256 amount,
        uint256 updatedBalance
    ) internal {
        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(staker);

            capsule.updatePrincipalBalance(updatedBalance);
            if (_isWithdrawal(requestAct)) {
                capsule.updateWithdrawableBalance(amount);
            }
        } else {
            IVault vault = _getVault(token);

            vault.updatePrincipalBalance(staker, updatedBalance);
            if (_isWithdrawal(requestAct)) {
                vault.updateWithdrawableBalance(staker, amount, 0);
            }
        }
    }

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
