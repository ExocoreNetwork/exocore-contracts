pragma solidity ^0.8.19;

import {ControllerStorage} from "../storage/ControllerStorage.sol";
import {IController} from "../interfaces/IController.sol";
import {IGateway} from "../interfaces/IGateway.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract Controller is Initializable, ControllerStorage, IController {
    using SafeERC20 for IERC20;

    enum Action {
		DEPOSIT,
		WITHDRAWPRINCIPLEFROMEXOCORE,
		WITHDRAWREWARDFROMEXOCORE,
		DELEGATETO,
		UNDELEGATEFROM,
		UPDATEUSERSBALANCE
    }

    struct InterchainMsgPayload {
        Action action;
        bytes actionArgs;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "only callable for admin");
        _;
    }

    modifier onlyGateway() {
        require(msg.sender == address(gateway), "only callable for gateway");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address[] calldata _tokenWhitelist,
        address _gateway, uint16 _ExocoreChainID,
        address _ExocoreGateway,
        address payable _admin
    ) external initializer {
        require(_gateway != address(0), "empty gateway address");
        require(_ExocoreGateway != address(0), "empty exocore chain gateway contract address");

        for (uint i = 0; i < _tokenWhitelist.length; i++) {
            tokenWhitelist[_tokenWhitelist[i]] = true;
        }

        gateway = IGateway(_gateway);
        ExocoreChainID = _ExocoreChainID;
        ExocoreGateway = IGateway(_ExocoreGateway);
        admin = _admin;
    }

    function deposit(address token, uint256 amount) payable external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        vault.deposit(msg.sender, amount);

        bytes memory actionArgs = abi.encodePacked(token, msg.sender, amount);
        _sendInterchainMsg(Action.DEPOSIT, actionArgs);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(principleAmount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(token, msg.sender, principleAmount);
        _sendInterchainMsg(Action.WITHDRAWPRINCIPLEFROMEXOCORE, actionArgs);
    }

    function claim(address token, uint256 amount, address recipient) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        vault.withdraw(recipient, amount);
    }

    function updateUsersBalance(UserBalanceUpdateInfo[] calldata info) external onlyGateway {
        for (uint i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint j = 0; j < userBalanceUpdate.tokenInfo.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenInfo[j];
                require(tokenWhitelist[tokenBalanceUpdate.token], "not whitelisted token");
                
                IVault vault = tokenVaults[tokenBalanceUpdate.token];
                require(address(vault) != address(0), "no vault added for this token");

                if (tokenBalanceUpdate.lastlyUpdatedPrincipleBalance > 0) {
                    vault.updatePrincipleBalance(userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedPrincipleBalance);
                }

                if (tokenBalanceUpdate.lastlyUpdatedRewardBalance > 0) {
                    vault.updateRewardBalance(userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedRewardBalance);
                }

                if (tokenBalanceUpdate.unlockPrincipleAmount > 0 || tokenBalanceUpdate.unlockRewardAmount > 0) {
                    vault.updateWithdrawableBalance(
                        userBalanceUpdate.user, 
                        tokenBalanceUpdate.unlockPrincipleAmount,
                        tokenBalanceUpdate.unlockRewardAmount
                    );
                }
            }
        }
    }

    function delegateTo(bytes32 operator, address token, uint256 amount) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(token, operator, msg.sender, amount);
        _sendInterchainMsg(Action.DELEGATETO, actionArgs);
    }

    function undelegateFrom(bytes32 operator, address token, uint256 amount) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(token, operator, msg.sender, amount);
        _sendInterchainMsg(Action.UNDELEGATEFROM, actionArgs);
    }

    function _sendInterchainMsg(Action act, bytes memory actionArgs) internal {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        gateway.sendInterchainMsg(ExocoreChainID, payload, admin, address(0), "");
    }
}