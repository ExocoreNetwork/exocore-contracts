pragma solidity ^0.8.19;

import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ILayerZeroEndpointUpgradeable} from "@layerzero-contracts/contracts-upgradable/interfaces/ILayerZeroEndpointUpgradeable.sol";
import {LzAppUpgradeable} from "../lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ExocoreReceiver is Initializable, LzAppUpgradeable {
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

    function initialize(address _ExocoreValidatorSetAddress, address _lzEndpoint) external initializer {
        require(_ExocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");
        require(_lzEndpoint != address(0), "invalid layerzero endpoint address");
        lzEndpoint = ILayerZeroEndpointUpgradeable(_lzEndpoint);
        ExocoreValidatorSetAddress = _ExocoreValidatorSetAddress;
        _transferOwnership(ExocoreValidatorSetAddress);
    }

    function _blockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual override {
        address fromAddress;
        assembly {
            fromAddress := mload(add(_srcAddress, 20))
        }
        emit InterchainMsgReceived(_srcChainId, abi.encodePacked(bytes20(fromAddress)), _nonce, _payload);
    }
}