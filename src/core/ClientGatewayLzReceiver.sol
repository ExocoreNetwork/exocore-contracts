pragma solidity ^0.8.19;

import {BootstrapLzReceiver} from "./BootstrapLzReceiver.sol";
import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {Origin} from "../lzApp/OAppReceiverUpgradeable.sol";

abstract contract ClientGatewayLzReceiver is BootstrapLzReceiver, ClientChainGatewayStorage {
    function _lzReceive(
        Origin calldata _origin, bytes calldata payload
    ) internal virtual override(BootstrapLzReceiver) {
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
                emit UnsupportedRequestEvent(act);
                revert UnsupportedRequest(act);
            }

            (bool success, bytes memory reason) =
                address(this).call(abi.encodePacked(selector_, abi.encode(payload[1:])));
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, _origin.nonce, reason);
            }
        }
    }
}
