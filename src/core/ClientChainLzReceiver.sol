pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ILayerZeroReceiver} from "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroReceiver.sol";

abstract contract ClientChainLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, ClientChainGatewayStorage {
    using SafeERC20 for IERC20;

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "ClientChainLzReceiver: could only be called from this contract itself with low level call");
        _;
    }

    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override {
        if (_origin.srcEid != exocoreChainId) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }

        _consumeInboundNonce(_origin.srcEid, _origin.sender, _origin.nonce);

        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            uint64 requestId = uint64(bytes8(payload[1:9]));

            Action requestAct = registeredRequestActions[requestId];
            bytes4 hookSelector = registeredResponseHooks[requestAct];
            if (hookSelector == bytes4(0)) {
                revert UnsupportedResponse(act);
            }

            bytes memory requestPayload = registeredRequests[requestId];
            if (requestPayload.length == 0) {
                revert UnexpectedResponse(requestId);
            }

            (bool success, bytes memory reason) =
                address(this).call(abi.encodePacked(hookSelector, abi.encode(requestPayload, payload[9:])));
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
            }

            delete registeredRequests[requestId];
        } else {
            bytes4 selector_ = whiteListFunctionSelectors[act];
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
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

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
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

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
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

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
