pragma solidity ^0.8.19;

import {GatewayStorage} from "../storage/GatewayStorage.sol";
import {ITSSReceiver} from "../interfaces/ITSSReceiver.sol";
import {IController} from "../interfaces/IController.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {ILayerZeroReceiver} from "@layerzero-contracts/interfaces/ILayerZeroReceiver.sol";
import {ILayerZeroEndpoint} from "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import {LzAppUpgradeable} from "../lzApp/LzAppUpgradeable.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BytesLib} from "@layerzero-contracts/util/BytesLib.sol";

contract ClientChainGateway is 
    Initializable,
    OwnableUpgradeable,
    GatewayStorage,
    ITSSReceiver,
    IController,
    LzAppUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);
    event RequestSent(Action indexed act, bytes payload);
    error UnAuthorizedSigner();
    error UnAuthorizedToken();
    error UnSupportedFunction();
    error VaultNotExist();
    error CommandExecutionFailure(Action act, bytes payload, bytes reason);

    modifier onlyCalledFromThis() {
        require(msg.sender == address(this), "could only be called from this contract itself with low level call");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address payable _ExocoreValidatorSetAddress,
        address[] calldata _whitelistTokens,
        address _lzEndpoint,
        uint16 _ExocoreChainID,
        address _ExocoreReceiver
    ) external initializer {
        require(_ExocoreReceiver != address(0), "invalid empty exocore chain gateway contract address");
        require(_ExocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");
        ExocoreValidatorSetAddress = _ExocoreValidatorSetAddress;
        _transferOwnership(ExocoreValidatorSetAddress);

        for (uint i = 0; i < _whitelistTokens.length; i++) {
            whitelistTokens[_whitelistTokens[i]] = true;
        }

        ExocoreChainID = _ExocoreChainID;
        ExocoreReceiver = ILayerZeroReceiver(_ExocoreReceiver);
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);

        whiteListFunctionSelectors[Action.UPDATE_USERS_BALANCES] = this.updateUsersBalances.selector;
        whiteListFunctionSelectors[Action.REPLY_DEPOSIT] = this.replyDeposit.selector;
        whiteListFunctionSelectors[Action.REPLY_WITHDRAW_PRINCIPLE_FROM_EXOCORE] = this.replyWithdrawPrincipleFromExocore.selector;
        whiteListFunctionSelectors[Action.REPLY_DELEGATE_TO] = this.replyDelegateTo.selector;
        whiteListFunctionSelectors[Action.REPLY_UNDELEGATE_FROM] = this.replyUndelegateFrom.selector;
    }

    function addTokenVaults(address[] calldata vaults) external onlyOwner {
        for (uint i =0; i < vaults.length; i++) {
            address underlyingToken = IVault(vaults[i]).getUnderlyingToken();
            if (!whitelistTokens[underlyingToken]) {
                revert UnAuthorizedToken();
            }
            tokenVaults[underlyingToken] = IVault(vaults[i]);
        }
    }

    function deposit(address token, uint256 amount) payable external {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        vault.deposit(msg.sender, amount);

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_DEPOSIT, actionArgs);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external {
        require(whitelistTokens[token], "not whitelisted token");
        require(principleAmount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), principleAmount);
        _sendInterchainMsg(Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, actionArgs);
    }

    function claim(address token, uint256 amount, address recipient) external {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        vault.withdraw(msg.sender, recipient, amount);
    }

    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) public {
        require(msg.sender == address(this), "caller must be client chain gateway itself");
        for (uint i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint j = 0; j < userBalanceUpdate.tokenBalances.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenBalances[j];
                require(whitelistTokens[tokenBalanceUpdate.token], "not whitelisted token");
                
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
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), operator, bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_DELEGATE_TO, actionArgs);
    }

    function undelegateFrom(bytes32 operator, address token, uint256 amount) external {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), operator, bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_UNDELEGATE_FROM, actionArgs);
    }

    function receiveInterchainMsg(InterchainMsg calldata _msg, bytes calldata signature) external {
        require(_msg.nonce == ++lastMessageNonce, "wrong message nonce");
        require(_msg.srcChainID == ExocoreChainID, "wrong source chain id");
        require(keccak256(_msg.srcAddress) == keccak256(bytes("0x")), "wrong source address");
        require(_msg.dstChainID == block.chainid, "mismatch destination chain id");
        require(keccak256(_msg.dstAddress) == keccak256(abi.encodePacked(address(this))), "mismatch destination contract address");
        bool isValid = verifyInterchainMsg(_msg, signature);
        if (!isValid) {
            revert UnAuthorizedSigner();
        }
        
        Action act = Action(uint8(_msg.payload[0]));
        require(act == Action.UPDATE_USERS_BALANCES, "not supported action");
        bytes memory args = _msg.payload[1:];
        (bool success, bytes memory reason) = address(this).call(abi.encodePacked(whiteListFunctionSelectors[act], args));
        if (!success) {
            emit MessageFailed(_msg.srcChainID, _msg.srcAddress, _msg.nonce, _msg.payload, reason);
        } else {
            emit MessageProcessed(_msg.srcChainID, _msg.srcAddress, _msg.nonce, _msg.payload);
        }
    }

    function _sendInterchainMsg(Action act, bytes memory actionArgs) internal {
        bytes memory payload = abi.encodePacked(act, actionArgs);
        (uint256 lzFee, ) = lzEndpoint.estimateFees(ExocoreChainID, address(this), payload, false, "");
        _lzSend(ExocoreChainID, payload, ExocoreValidatorSetAddress, address(0), "", lzFee);
        emit RequestSent(act, payload);
    }

    function verifyInterchainMsg(InterchainMsg calldata _msg, bytes calldata signature) internal view returns(bool isValid) {
        bytes32 digest = keccak256(abi.encodePacked(_msg.srcChainID, _msg.srcAddress, _msg.dstChainID, _msg.dstAddress, _msg.nonce, _msg.payload));
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        address signer = digest.recover(v, r, s);
        if (signer == ExocoreValidatorSetAddress) {
            isValid = true;
        }
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65);

        assembly {
            // first 32 bytes, after the length prefix.
            r := mload(add(sig, 32))
            // second 32 bytes.
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes).
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function _blockingLzReceive(uint16, bytes memory, uint64, bytes calldata payload) internal virtual override {
        Action act = Action(uint8(payload[0]));
        bytes4 selector_ = whiteListFunctionSelectors[act];
        if (selector_ == bytes4(0)) {
            revert UnSupportedFunction();
        }

        (bool success, bytes memory reason) = address(this).call(abi.encodePacked(selector_, payload[1:]));
        if (!success) {
            revert CommandExecutionFailure(act, payload, reason);
        }
    }

    function replyDeposit(
        bool success, 
        address token, 
        address depositor, 
        uint256 amount, 
        uint256 lastlyUpdatedPrincipleBalance
    ) public onlyCalledFromThis {
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updatePrincipleBalance(depositor, lastlyUpdatedPrincipleBalance);
        }

        emit DepositResult(success, depositor, amount);
    }

    function replyWithdrawPrincipleFromExocore(
        bool success, 
        address token, 
        address withdrawer, 
        uint256 unlockPrincipleAmount,
        uint256 lastlyUpdatedPrincipleBalance
    ) public onlyCalledFromThis {
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updatePrincipleBalance(withdrawer, lastlyUpdatedPrincipleBalance);
            vault.updateWithdrawableBalance(withdrawer, unlockPrincipleAmount, 0);
        }

        emit WithdrawResult(success, withdrawer, unlockPrincipleAmount);
    }

    function replyDelegateTo(
        bool success,
        bytes32 operator,
        address token,
        address delegator,
        uint256 amount
    ) public onlyCalledFromThis {
        emit DelegateResult(success, delegator, operator, token, amount);
    }

    function replyUndelegateFrom(
        bool success,
        bytes32 operator,
        address token,
        address undelegator,
        uint256 amount
    ) public onlyCalledFromThis {
        emit UndelegateResult(success, undelegator, operator, token, amount);
    }
}