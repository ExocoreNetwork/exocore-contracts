pragma solidity ^0.8.19;

import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IVault} from "../interfaces/IVault.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract ClientGatewayLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {

    error UnsupportedResponse(Action act);
    error UnexpectedResponse(uint64 nonce);
    error DepositShouldNotFailOnExocore(address token, address depositor);

    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "ClientChainLzReceiver: could only be called from this contract itself with low level call"
        );
        _;
    }

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

    function nextNonce(uint32 srcEid, bytes32 sender)
        public
        view
        virtual
        override(OAppReceiverUpgradeable)
        returns (uint64)
    {
        return inboundNonce[srcEid][sender] + 1;
    }

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

    function afterReceiveWithdrawPrincipalResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockPrincipalAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipalBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = _getVault(token);

            vault.updatePrincipalBalance(withdrawer, lastlyUpdatedPrincipalBalance);
            vault.updateWithdrawableBalance(withdrawer, unlockPrincipalAmount, 0);
        }

        emit WithdrawPrincipalResult(success, token, withdrawer, unlockPrincipalAmount);
    }

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

    function afterReceiveDelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address delegator, string memory operator, uint256 amount) =
            abi.decode(requestPayload, (address, address, string, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit DelegateResult(success, delegator, operator, token, amount);
    }

    function afterReceiveUndelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address undelegator, string memory operator, uint256 amount) =
            abi.decode(requestPayload, (address, address, string, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit UndelegateResult(success, undelegator, operator, token, amount);
    }

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

    function afterReceiveRegisterTokensResponse(bytes calldata requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
        whenNotPaused
    {
        address[] memory tokens = abi.decode(requestPayload, (address[]));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        if (success) {
            for (uint256 i; i < tokens.length; i++) {
                address token = tokens[i];
                isWhitelistedToken[token] = true;
                whitelistTokens.push(token);

                // deploy the corresponding vault if not deployed before
                if (address(tokenToVault[token]) == address(0)) {
                    _deployVault(token);
                }

                emit WhitelistTokenAdded(token);
            }
        }

        emit RegisterTokensResult(success);
    }

}
