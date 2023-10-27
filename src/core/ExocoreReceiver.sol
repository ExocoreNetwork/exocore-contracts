pragma solidity ^0.8.19;

import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {LzAppUpgradeable} from "@layerzero-contracts/contracts-upgradable/lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ExocoreGateway is Initializable, LzAppUpgradeable {
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

    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        emit InterchainMsgReceived(_srcChainId, _srcAddress, _nonce, _payload);
    }
}