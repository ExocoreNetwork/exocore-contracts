pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {ILayerZeroReceiver} from "@layerzero-contracts/interfaces/ILayerZeroReceiver.sol";
import {IVault} from "../interfaces/IVault.sol";

contract GatewayStorage {
    enum Action {
		REQUEST_DEPOSIT,
		REPLY_DEPOSIT,
		REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
    REPLY_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
		REQUEST_DELEGATE_TO,
    REPLY_DELEGATE_TO,
		REQUEST_UNDELEGATE_FROM,
    REPLY_UNDELEGATE_FROM,
		UPDATE_USERS_BALANCES
    }

    address payable public ExocoreValidatorSetAddress;
    
    uint256 lastMessageNonce;
    mapping(uint16 => uint256) public payloadSizeLimit;
    mapping(Action => bytes4) public whiteListFunctionSelectors;

    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    ILayerZeroReceiver public ExocoreReceiver;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}