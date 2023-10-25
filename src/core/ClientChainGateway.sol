pragma solidity ^0.8.19;

import {IController} from "../interfaces/IController.sol";
import {Controller} from "./Controller.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ClientChainGateway is Initializable, GatewayStorage, IGateway {
    using ECDSA for bytes32;
    using BytesLib for bytes;

    modifier onlyController() {
        require(msg.sender == address(controller), "only callable for controller");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _lzEndpoint, uint256 _lzFee) external initializer {
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);
        lzFee = _lzFee;
    }

    function sendInterchainMsg(uint16 _dstChainId, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes memory _adapterParams) external payable onlyController {
       lzEndpoint.send{value: lzFee}(_dstChainId, trustedRemote[_dstChainId], _payload, _refundAddress, _zroPaymentAddress, _adapterParams);
    }

    function receiveInterchainMsg(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload, bytes calldata sig) external {
        bytes32 _hash = keccak256(abi.encodePacked(_srcChainId, _srcAddress, _payload, _nonce, _payload));
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        address signer = _hash.recover(v, r, s);
        require(signer == ExocoreValidatorSetPubkey, "invalid interchain message sent from unauthorized party");

        Controller.Action act = Controller.Action(uint8(_payload[0]));
        bytes4 functionSig = whiteListFunctionSigs[act];
        require(functionSig != bytes4(0), "no valid function signatures for action");
        bytes memory args = _payload.slice(1, _payload.length-1);

        address callee = address(uint160(bytes20(_srcAddress)));

        (bool success, bytes memory data) = callee.call(abi.encodePacked(functionSig, args));
        require(success, "function call failed");
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
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