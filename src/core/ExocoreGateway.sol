pragma solidity ^0.8.19;

import {IController} from "../interfaces/IController.sol";
import {Controller} from "./Controller.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {LzAppUpgradeable} from "@layerzero-contracts/contracts-upgradable/lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ExocoreGateway is Initializable, GatewayStorage, IGateway, LzAppUpgradeable {
    modifier onlyLzEndpoint() {
        require(msg.sender == address(lzEndpoint), "only callable for layerzero endpoint");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _lzEndpoint, uint256 _lzFee) external initializer {
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);
        lzFee = _lzFee;
    }

    function sendInterchainMsg(uint16 _dstChainId, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes memory _adapterParams) external payable {
        revert("not supported yet");
    }

    function receiveInterchainMsg(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload, bytes calldata sig) external {
        bytes32 _hash = keccak256(abi.encodePacked(_srcChainId, _srcAddress, _payload, _nonce, _payload));
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        address signer = _hash.recover(v, r, s);
        require(signer == ExocoreValidatorSetPubkey, "invalid interchain message sent from unauthorized party");
        
        emit InterchainMsgReceived(_srcChainId, _srcAddress, _nonce, _payload);
    }

    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        emit InterchainMsgReceived(_srcChainId, _srcAddress, _nonce, _payload);
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