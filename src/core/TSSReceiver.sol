pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {IController} from "../interfaces/IController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {OAppUpgradeable} from "../lzApp/OAppUpgradeable.sol";
import {ECDSA} from "@openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

abstract contract TSSReceiver is PausableUpgradeable, ClientChainGatewayStorage, ITSSReceiver {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    function receiveInterchainMsg(InterchainMsg calldata _msg, bytes calldata signature) external whenNotPaused {
        require(_msg.nonce == ++lastMessageNonce, "TSSReceiver: message nonce is not expected");
        require(_msg.srcChainID == exocoreChainId, "TSSReceiver: source chain id is incorrect");
        require(keccak256(_msg.srcAddress) == keccak256(bytes("0x")), "TSSReceiver: source address is incorrect");
        require(_msg.dstChainID == block.chainid, "TSSReceiver: destination chain id is not matched with this chain");
        require(
            keccak256(_msg.dstAddress) == keccak256(abi.encodePacked(address(this))),
            "TSSReceiver: destination contract address is not matched with this contract"
        );
        bool isValid = verifyInterchainMsg(_msg, signature);
        if (!isValid) {
            revert UnauthorizedSigner();
        }

        Action act = Action(uint8(_msg.payload[0]));
        require(act == Action.UPDATE_USERS_BALANCES, "TSSReceiver: action in message payload is not UPDATE_USERS_BALANCES");
        bytes memory args = _msg.payload[1:];
        (bool success, bytes memory reason) =
            address(this).call(abi.encodePacked(whiteListFunctionSelectors[act], args));
        if (!success) {
            emit MessageFailed(_msg.srcChainID, _msg.srcAddress, _msg.nonce, _msg.payload, reason);
        } else {
            emit MessageProcessed(_msg.srcChainID, _msg.srcAddress, _msg.nonce, _msg.payload);
        }
    }

    function verifyInterchainMsg(InterchainMsg calldata msg_, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                msg_.srcChainID, msg_.srcAddress, msg_.dstChainID, msg_.dstAddress, msg_.nonce, msg_.payload
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        address signer = digest.recover(v, r, s);
        if (signer == exocoreValidatorSetAddress) {
            isValid = true;
        }
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }
}
