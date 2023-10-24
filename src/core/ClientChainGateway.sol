pragma solidity ^0.8.19;

import {IController} from "../interfaces/IController.sol";
import {Controller} from "./Controller.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract Gateway is Initializable, GatewayStorage, IGateway {
    using ECDSA for bytes32;
    using BytesLib for bytes;

    modifier onlyController() {
        require(msg.sender == address(controller), "only callable for controller");
        _;
    }

    constructor(address _lzEndpoint) {
        _disableInitializers();
    }

    function initialize(address _lzEndpoint, uint256 _lzFee) external initializer {
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);
        lzFee = _lzFee;
    }

    function sendInterchainMsg(InterchainMsg calldata _msg) external payable onlyController {
       lzEndpoint.send{value: lzFee}(_msg.dstChainID, _msg.dstAddress, _msg.payload, _msg.refundAddress, address(0), _msg.params);
    }

    function receiveInterchainMsg(InterchainMsg calldata _msg, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 _hash = keccak256(abi.encode(_msg.dstChainID, _msg.dstAddress, _msg.payload, _msg.refundAddress, _msg.interchainFuelAddress, _msg.params));
        address signer = _hash.recover(v, r, s);
        require(signer == ExocoreValidatorSetBLSPubkey, "invalid interchain message sent from unauthorized party");

        Controller.Action act = Controller.Action(uint8(_msg.payload[0]));
        bytes4 functionSig = whiteListedFunctionSigs[act];
        require(functionSig != bytes4(0), "no valid function signatures for action");
        bytes memory args = _msg.payload.slice(1, _msg.payload.length-1);

        address callee = address(uint160(bytes20(_msg.dstAddress)));

        (bool success, bytes memory data) = callee.call(abi.encode(functionSig, args));
        require(success, "function call failed");
    }
} 