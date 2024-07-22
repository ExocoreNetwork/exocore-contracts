// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";

/// @title BootstrapLzReceiver
/// @author ExocoreNetwork
/// @notice The base contract for the BootstrapLzReceiver. It only receives messages from the Exocore chain and does not
/// send any.
/// @dev This contract is abstract because it does not call the base contract's constructor.
abstract contract BootstrapLzReceiver is PausableUpgradeable, OAppReceiverUpgradeable, BootstrapStorage {

    /// @dev Allows only this contract to call the function via low level call.
    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "BootstrapLzReceiver: could only be called from this contract itself with low level call"
        );
        _;
    }

    /// @inheritdoc OAppReceiverUpgradeable
    function _lzReceive(Origin calldata _origin, bytes calldata payload) internal virtual override {
        if (_origin.srcEid != EXOCORE_CHAIN_ID) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }
        _verifyAndUpdateNonce(_origin.srcEid, _origin.sender, _origin.nonce);
        Action act = Action(uint8(payload[0]));
        require(act != Action.RESPOND, "BootstrapLzReceiver: invalid action");
        bytes4 selector_ = _whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert UnsupportedRequest(act);
        }
        (bool success, bytes memory reason) = address(this).call(abi.encodePacked(selector_, abi.encode(payload[1:])));
        if (!success) {
            revert RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
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

}
