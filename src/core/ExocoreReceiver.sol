pragma solidity ^0.8.19;

import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpointUpgradeable} from "@layerzero-contracts/contracts-upgradable/interfaces/ILayerZeroEndpointUpgradeable.sol";
import {LzAppUpgradeable} from "../lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ExocoreGateway is Initializable, LzAppUpgradeable {
    event InterchainMsgReceived(
        uint16 indexed srcChainID,
        bytes indexed srcChainAddress,
        uint64 indexed nonce,
        bytes payload
    );

    modifier onlyLzEndpoint() {
        require(msg.sender == address(lzEndpoint), "only callable for layerzero endpoint");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _lzEndpoint) external initializer {
        lzEndpoint = ILayerZeroEndpointUpgradeable(_lzEndpoint);
    }

    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        emit InterchainMsgReceived(_srcChainId, _srcAddress, _nonce, _payload);
    }
}