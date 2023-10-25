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

    }

    function receiveInterchainMsg(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload, bytes calldata sig) external {

    }

    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        
    }
}