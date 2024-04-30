pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";

import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract ClientChainLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {
    event DepositResult(bool indexed success, address indexed token, address indexed depositor, uint256 amount);
    event WithdrawPrincipleResult(
        bool indexed success, address indexed token, address indexed withdrawer, uint256 amount
    );
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);
    event DelegateResult(
        bool indexed success, address indexed delegator, string delegatee, address token, uint256 amount
    );
    event UndelegateResult(
        bool indexed success, address indexed undelegator, string indexed undelegatee, address token, uint256 amount
    );

    error UnsupportedRequest(Action act);
    error UnsupportedResponse(Action act);
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);
    error UnexpectedResponse(uint64 nonce);
    error UnexpectedInboundNonce(uint64 expectedNonce, uint64 actualNonce);
    error UnexpectedSourceChain(uint32 unexpectedSrcEndpointId);
    error DepositShouldNotFailOnExocore(address token, address depositor);

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "ClientChainLzReceiver: could only be called from this contract itself with low level call");
        _;
    }

    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override whenNotPaused {
        if (_origin.srcEid != exocoreChainId) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }

        _consumeInboundNonce(_origin.srcEid, _origin.sender, _origin.nonce);

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

    function _consumeInboundNonce(uint32 srcEid, bytes32 sender, uint64 nonce) internal {
        inboundNonce[srcEid][sender] += 1;
        if (nonce != inboundNonce[srcEid][sender]) {
            revert UnexpectedInboundNonce(inboundNonce[srcEid][sender], nonce);
        }
    }

    function afterReceiveDepositResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address depositor, uint256 amount) = abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:]));

        if (!success) {
            revert DepositShouldNotFailOnExocore(token, depositor);
        }

        if (token == VIRTUAL_STAKED_ETH_ADDRESS) {
            IExoCapsule capsule = _getCapsule(depositor);
            capsule.updatePrincipleBalance(lastlyUpdatedPrincipleBalance);
        } else {
            IVault vault = _getVault(token);
            vault.updatePrincipleBalance(depositor, lastlyUpdatedPrincipleBalance);
        }

        emit DepositResult(success, token, depositor, amount);
    }

    function afterReceiveWithdrawPrincipleResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, address withdrawer, uint256 unlockPrincipleAmount) =
            abi.decode(requestPayload, (address, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = _getVault(token);

            vault.updatePrincipleBalance(withdrawer, lastlyUpdatedPrincipleBalance);
            vault.updateWithdrawableBalance(withdrawer, unlockPrincipleAmount, 0);
        }

        emit WithdrawPrincipleResult(success, token, withdrawer, unlockPrincipleAmount);
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
        (address token, string memory operator, address delegator, uint256 amount) =
            abi.decode(requestPayload, (address, string, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit DelegateResult(success, delegator, operator, token, amount);
    }

    function afterReceiveUndelegateResponse(bytes memory requestPayload, bytes calldata responsePayload)
        public
        onlyCalledFromThis
    {
        (address token, string memory operator, address undelegator, uint256 amount) =
            abi.decode(requestPayload, (address, string, address, uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit UndelegateResult(success, undelegator, operator, token, amount);
    }
}
