pragma solidity ^0.8.19;

import {BootstrapStorage} from "../storage/BootstrapStorage.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OAppReceiverUpgradeable, Origin} from "../lzApp/OAppReceiverUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract BootstrapLzReceiver is
    PausableUpgradeable,
    OAppReceiverUpgradeable,
    BootstrapStorage
{
    modifier onlyCalledFromThis() {
        require(
            msg.sender == address(this),
            "BootstrapLzReceiver: could only be called from this contract itself with low level call"
        );
        _;
    }

    function _lzReceive(
        Origin calldata _origin, bytes calldata payload
    ) internal virtual override {
        if (_origin.srcEid != exocoreChainId) {
            revert UnexpectedSourceChain(_origin.srcEid);
        }
        _consumeInboundNonce(_origin.srcEid, _origin.sender, _origin.nonce);
        Action act = Action(uint8(payload[0]));
        require(act != Action.RESPOND, "BootstrapLzReceiver: invalid action");
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
}
