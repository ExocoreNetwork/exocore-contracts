pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {ILayerZeroReceiver} from "@layerzero-contracts/interfaces/ILayerZeroReceiver.sol";
import {IVault} from "../interfaces/IVault.sol";


contract GatewayStorage {
    enum Action {
		DEPOSIT,
		WITHDRAWPRINCIPLEFROMEXOCORE,
		WITHDRAWREWARDFROMEXOCORE,
		DELEGATETO,
		UNDELEGATEFROM,
		UPDATEUSERSBALANCE
    }

    address public ExocoreValidatorSetPubkey;
    
    ILayerZeroEndpoint public lzEndpoint;
    uint256 public lzFee;
    uint256 lastMessageNonce;
    mapping(uint16 => bytes) public trustedRemote;
    mapping(uint16 => uint256) public payloadSizeLimit;
    mapping(Action => bytes4) public whiteListFunctionSelectors;

    mapping(address => bool) public whitelistTokens;
    mapping(address => IVault) public tokenVaults;
    ILayerZeroReceiver public ExocoreReceiver;
    address payable public admin;
    uint16 public ExocoreChainID;

    uint256[40] private __gap;
}