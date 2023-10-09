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

    modifier onlyAdmin() {
        require(msg.sender == admin, "only callable for admin");
        _;
    }

    modifier onlyGateway() {
        require(msg.sender == gateway, "only callable for gateway");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address[] calldata _tokenWhitelist,
        address _gateway, uint16 _ExocoreChainID,
        address _ExocoreGateway,
        address _admin
    ) external initializer {
        require(_gateway != address(0), "empty gateway address");
        require(_ExocoreGateway != address(0), "empty exocore chain receiver contract address");

        for (uint i = 0; i < _tokenWhitelist.length; i++) {
            tokenWhitelist[_tokenWhitelist[i]] = true;
        }

        gateway = _gateway;
        ExocoreChainID = _ExocoreChainID;
        ExocoreGateway = _ExocoreGateway;
        admin = _admin;
    }

    function deposit(address token, uint256 amount) payable external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        address vault = tokenVaults[token];
        require(vault != address(0), "no vault added for this token");

        IVault(vault).deposit(msg.sender, amount);

        bytes memory payload = abi.encode("deposit", token, amount);
        IGateway.InterchainMsg memory depositMsg = IGateway.InterchainMsg(
            ExocoreChainID,
            abi.encodePacked(ExocoreGateway),
            payload,
            payable(msg.sender),
            payable(msg.sender),
            ""
        );

        IGateway(gateway).sendInterchainMsg(depositMsg);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(principleAmount > 0, "amount should be greater than zero");
        
        address vault = tokenVaults[token];
        require(vault != address(0), "no vault added for this token");

        bytes memory payload = abi.encode("withdrawPrincipleFromExocore", token, principleAmount);
        IGateway.InterchainMsg memory withdrawPrincipleMsg = IGateway.InterchainMsg(
            ExocoreChainID,
            abi.encodePacked(ExocoreGateway),
            payload,
            payable(msg.sender),
            payable(msg.sender),
            ""
        );

        IGateway(gateway).sendInterchainMsg(withdrawPrincipleMsg);
    }

    function claim(address token, uint256 amount, address recipient) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        address vault = tokenVaults[token];
        require(vault != address(0), "no vault added for this token");

        IVault(vault).withdraw(recipient, amount);
    }

    function updateUsersBalance(UserBalanceUpdateInfo[] calldata info) external onlyGateway {
        for (uint i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint j = 0; j < userBalanceUpdate.tokenInfo.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenInfo[j];
                require(tokenWhitelist[tokenBalanceUpdate.token], "not whitelisted token");
                
                address vault = tokenVaults[tokenBalanceUpdate.token];
                require(vault != address(0), "no vault added for this token");

                if (tokenBalanceUpdate.lastlyUpdatedPrincipleBalance > 0) {
                    IVault(vault).updatePrincipleBalance(userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedPrincipleBalance);
                }

                if (tokenBalanceUpdate.lastlyUpdatedRewardBalance > 0) {
                    IVault(vault).updateRewardBalance(userBalanceUpdate.user, tokenBalanceUpdate.lastlyUpdatedRewardBalance);
                }

                if (tokenBalanceUpdate.unlockAmount > 0) {
                    IVault(vault).updateWithdrawableBalance(userBalanceUpdate.user, tokenBalanceUpdate.unlockAmount);
                }
            }
        }
    }

    function delegateTo(address operator, address token, uint256 amount) external {
        require(tokenWhitelist[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != address(0), "empty operator address");
        
        address vault = tokenVaults[token];
        require(vault != address(0), "no vault added for this token");

        bytes memory payload = abi.encode("delegateTo", operator, token, amount);
        IGateway.InterchainMsg memory delegateMsg = IGateway.InterchainMsg(
            ExocoreChainID,
            abi.encodePacked(ExocoreGateway),
            payload,
            payable(msg.sender),
            payable(msg.sender),
            ""
        );

        IGateway(gateway).sendInterchainMsg(delegateMsg);
    }
}