pragma solidity ^0.8.19;

import {ExocoreGatewayStorage} from "../storage/ExocoreGatewayStorage.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {LzAppUpgradeable} from "../lzApp/LzAppUpgradeable.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ExocoreGateway is LzAppUpgradeable, ExocoreGatewayStorage {
    error UnSupportedFunction();
    error CommandExecutionFailure(Action act, bytes payload, bytes reason);

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
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);
        _transferOwnership(_ExocoreValidatorSetAddress);

        whiteListFunctionSelectors[Action.REQUEST_DEPOSIT] = bytes4(keccak256("deposit(uint16,bytes,bytes,uint256)"));
        whiteListFunctionSelectors[Action.REQUEST_DELEGATE_TO] = bytes4(keccak256("delegateToThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));
        whiteListFunctionSelectors[Action.REQUEST_UNDELEGATE_FROM] = bytes4(keccak256("undelegateFromThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)"));
    }

    function _blockingLzReceive(uint16 srcChainId, bytes memory srcAddress, uint64 nonce, bytes calldata payload) internal virtual override {
        address fromAddress;
        assembly {
            fromAddress := mload(add(srcAddress, 20))
        }

        Action act = Action(uint8(payload[0]));
        if (act == Action.REQUEST_DEPOSIT) {
            bytes memory token = payload[1:33];
            bytes memory depositor = payload[33:65];
            uint256 amount = uint256(bytes32(payload[65:97]));
            (bool success, bytes memory depositResponse) = _deposit(srcChainId, token, depositor, amount);

            bytes memory actionArgs = abi.encodePacked(success, depositResponse);
            _sendInterchainMsg(srcChainId, Action.REPLY_DEPOSIT, actionArgs);
        } else if (act == Action.REPLY_DELEGATE_TO) {
            bytes memory token = payload[1:33];
            bytes memory operator = payload[33:65];
            bytes memory delegator = payload[65:97];
            uint256 amount = uint256(bytes32(payload[97:129]));
            (bool success, bytes memory delegateToResponse) = _delegateTo(srcChainId, nonce, token, delegator, operator, amount);

            bytes memory actionArgs = abi.encodePacked(success, delegateToResponse);
            _sendInterchainMsg(srcChainId, Action.REPLY_DELEGATE_TO, actionArgs);
        }
    }

    function _deposit(uint16 srcChainId, bytes memory token, bytes memory depositor, uint256 amount) internal returns(bool, bytes memory) {
        (bool success, bytes memory depositResponse) = DEPOSIT_PRECOMPILE_ADDRESS.call(abi.encodeWithSignature("deposit(uint16,bytes,bytes,uint256)", srcChainId, token, depositor, amount));
        return(success, depositResponse);
    }

    function _delegateTo(uint16 srcChainId, uint64 nonce, bytes memory token, bytes memory depositor, bytes memory operator, uint256 amount) internal returns(bool, bytes memory) {
        (bool success, bytes memory delegateToResponse) = DELEGATION_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSignature(
                "delegateToThroughClientChain(uint16,uint64,bytes,bytes,bytes,uint256)", 
                srcChainId,
                nonce, 
                token, 
                depositor,
                operator, 
                amount
            )
        );
        return(success, delegateToResponse);
    }

    function _sendInterchainMsg(uint16 srcChainId, Action act, bytes memory actionArgs) internal {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        (uint256 lzFee, ) = lzEndpoint.estimateFees(srcChainId, address(this), payload, false, "");
        _lzSend(srcChainId, payload, ExocoreValidatorSetAddress, address(0), "", lzFee);
    }
}