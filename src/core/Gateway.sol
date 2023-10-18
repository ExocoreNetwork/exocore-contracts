pragma solidity ^0.8.19;

import {IController} from "../interfaces/IController.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {NonblockingLzApp} from "@layerzero-contracts/lzApp/NonblockingLzApp.sol";

contract Gateway is GatewayStorage, IGateway, NonblockingLzApp {
    modifier onlyController() {
        require(msg.sender == address(controller), "only callable for controller");
        _;
    }

    constructor(address _lzEndpoint) NonblockingLzApp(_lzEndpoint) {}

    function sendInterchainMsg(InterchainMsg calldata _msg) external payable onlyController {
        _lzSend(_msg.dstChainID, _msg.payload, payable(owner()), address(0), _msg.params, lzFee);
    }

    function receiveInterchainMsg(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, InterchainMsg calldata _msg) external {
        lzReceive(_srcChainId, _srcAddress, _nonce, _msg.payload);
    }

    function _nonblockingLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal override {
        require(_payload.length > 20, "payload must at least contain target contract address bytes");
        bytes memory targetContractAddressBytes = new bytes(20);
        for (uint i =0; i < 20; i++) {
            targetContractAddressBytes[i] = _payload[i];
        }

        address targetContractAddress = address(uint160(bytes20(targetContractAddressBytes)));
    }
} 