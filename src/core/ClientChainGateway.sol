pragma solidity ^0.8.19;

import {ClientChainGatewayStorage} from "../storage/ClientChainGatewayStorage.sol";
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
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/security/PausableUpgradeable.sol";

contract ClientChainGateway is 
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ClientChainGatewayStorage,
    ITSSReceiver,
    IController,
    LzAppUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    event MessageProcessed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);
    event MessageFailed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload, bytes _reason);
    event RequestSent(Action indexed act);
    error UnauthorizedSigner();
    error UnauthorizedToken();
    error UnsupportedRequest(Action act);
    error UnsupportedResponse(Action act); 
    error RequestOrResponseExecuteFailed(Action act, uint64 nonce, bytes reason);
    error VaultNotExist();
    error ActionFailed(Action act, uint64 nonce);
    error UnexpectedResponse(uint64 nonce);

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
        uint16 _ExocoreChainID
    ) 
        external 
        initializer 
    {
        require(_ExocoreValidatorSetAddress != address(0), "invalid empty exocore validator set address");
        ExocoreValidatorSetAddress = _ExocoreValidatorSetAddress;

        for (uint i = 0; i < _whitelistTokens.length; i++) {
            whitelistTokens[_whitelistTokens[i]] = true;
        }

        ExocoreChainID = _ExocoreChainID;
        lzEndpoint = ILayerZeroEndpoint(_lzEndpoint);

        whiteListFunctionSelectors[Action.UPDATE_USERS_BALANCES] = this.updateUsersBalances.selector;

        registeredResponseHooks[Action.REQUEST_DEPOSIT] = this.afterReceiveDepositResponse.selector;
        registeredResponseHooks[Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE] = this.afterReceiveWithdrawPrincipleResponse.selector;
        registeredResponseHooks[Action.REQUEST_DELEGATE_TO] = this.afterReceiveDelegateResponse.selector;
        registeredResponseHooks[Action.REQUEST_UNDELEGATE_FROM] = this.afterReceiveUndelegateResponse.selector;

        _transferOwnership(ExocoreValidatorSetAddress);
        __Pausable_init();
    }

    function pause() external {
        require(msg.sender == ExocoreValidatorSetAddress, "only Exocore validator set aggregated address could call this");
        _pause();
    }

    function addTokenVaults(address[] calldata vaults) 
        external 
        onlyOwner
        whenNotPaused 
    {
        for (uint i =0; i < vaults.length; i++) {
            address underlyingToken = IVault(vaults[i]).getUnderlyingToken();
            if (!whitelistTokens[underlyingToken]) {
                revert UnauthorizedToken();
            }
            tokenVaults[underlyingToken] = IVault(vaults[i]);
        }
    }

    function deposit(address token, uint256 amount) payable external whenNotPaused {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        require(address(vault) != address(0), "no vault added for this token");

        vault.deposit(msg.sender, amount);

        uint64 lzNonce = lzEndpoint.getOutboundNonce(ExocoreChainID, address(this)) + 1;
        registeredRequests[lzNonce] = abi.encode(token, msg.sender, amount);
        registeredRequestActions[lzNonce] = Action.REQUEST_DEPOSIT;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_DEPOSIT, actionArgs);
    }

    function withdrawPrincipleFromExocore(address token, uint256 principleAmount) external whenNotPaused {
        require(whitelistTokens[token], "not whitelisted token");
        require(principleAmount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        uint64 lzNonce = lzEndpoint.getOutboundNonce(ExocoreChainID, address(this)) + 1;
        registeredRequests[lzNonce] = abi.encode(token, msg.sender, principleAmount);
        registeredRequestActions[lzNonce] = Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), bytes32(bytes20(msg.sender)), principleAmount);
        _sendInterchainMsg(Action.REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE, actionArgs);
    }

    function claim(address token, uint256 amount, address recipient) external whenNotPaused {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        vault.withdraw(msg.sender, recipient, amount);
    }

    function updateUsersBalances(UserBalanceUpdateInfo[] calldata info) public whenNotPaused {
        require(msg.sender == address(this), "caller must be client chain gateway itself");
        for (uint i = 0; i < info.length; i++) {
            UserBalanceUpdateInfo memory userBalanceUpdate = info[i];
            for (uint j = 0; j < userBalanceUpdate.tokenBalances.length; j++) {
                TokenBalanceUpdateInfo memory tokenBalanceUpdate = userBalanceUpdate.tokenBalances[j];
                require(whitelistTokens[tokenBalanceUpdate.token], "not whitelisted token");
                
                IVault vault = tokenVaults[tokenBalanceUpdate.token];
                if (address(vault) == address(0)) {
                    revert VaultNotExist();
                }

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

    function delegateTo(bytes32 operator, address token, uint256 amount) external whenNotPaused {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        uint64 lzNonce = lzEndpoint.getOutboundNonce(ExocoreChainID, address(this)) + 1;
        registeredRequests[lzNonce] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[lzNonce] = Action.REQUEST_DELEGATE_TO;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), operator, bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_DELEGATE_TO, actionArgs);
    }

    function undelegateFrom(bytes32 operator, address token, uint256 amount) external whenNotPaused {
        require(whitelistTokens[token], "not whitelisted token");
        require(amount > 0, "amount should be greater than zero");
        require(operator != bytes32(0), "empty operator address");
        
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        uint64 lzNonce = lzEndpoint.getOutboundNonce(ExocoreChainID, address(this)) + 1;
        registeredRequests[lzNonce] = abi.encode(token, operator, msg.sender, amount);
        registeredRequestActions[lzNonce] = Action.REQUEST_UNDELEGATE_FROM;

        bytes memory actionArgs = abi.encodePacked(bytes32(bytes20(token)), operator, bytes32(bytes20(msg.sender)), amount);
        _sendInterchainMsg(Action.REQUEST_UNDELEGATE_FROM, actionArgs);
    }

    function receiveInterchainMsg(InterchainMsg calldata _msg, bytes calldata signature) external whenNotPaused {
        require(_msg.nonce == ++lastMessageNonce, "wrong message nonce");
        require(_msg.srcChainID == ExocoreChainID, "wrong source chain id");
        require(keccak256(_msg.srcAddress) == keccak256(bytes("0x")), "wrong source address");
        require(_msg.dstChainID == block.chainid, "mismatch destination chain id");
        require(keccak256(_msg.dstAddress) == keccak256(abi.encodePacked(address(this))), "mismatch destination contract address");
        bool isValid = verifyInterchainMsg(_msg, signature);
        if (!isValid) {
            revert UnauthorizedSigner();
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
        emit RequestSent(act);
    }

    function verifyInterchainMsg(InterchainMsg calldata msg_, bytes calldata signature) internal view returns(bool isValid) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                msg_.srcChainID, 
                msg_.srcAddress, 
                msg_.dstChainID, 
                msg_.dstAddress, 
                msg_.nonce, 
                msg_.payload
            )
        );
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

    function _blockingLzReceive(uint16, bytes memory, uint64 nonce, bytes calldata payload) internal virtual override {
        Action act = Action(uint8(payload[0]));
        if (act == Action.RESPOND) {
            uint64 requestId = uint64(bytes8(payload[1:9]));

            Action requestAct = registeredRequestActions[requestId];
            bytes4 hookSelector = registeredResponseHooks[requestAct];
            if (hookSelector == bytes4(0)) {
                revert UnsupportedResponse(act);
            }

            bytes memory requestPayload = registeredRequests[requestId];
            if (requestPayload.length == 0) {
                revert UnexpectedResponse(requestId);
            }

            (bool success, bytes memory reason) = address(this).call(
                abi.encodePacked(
                    hookSelector, 
                    abi.encode(requestPayload, payload[9:])
                )
            );
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, nonce, reason);
            }

            delete registeredRequests[requestId];
        } else {
            bytes4 selector_ = whiteListFunctionSelectors[act];
            if (selector_ == bytes4(0)) {
                revert UnsupportedRequest(act);
            }

            (bool success, bytes memory reason) = address(this).call(abi.encodePacked(selector_, abi.encode(payload[1:])));
            if (!success) {
                revert RequestOrResponseExecuteFailed(act, nonce, reason);
            }
        }
    }

    function afterReceiveDepositResponse(bytes memory requestPayload, bytes calldata responsePayload) 
        public 
        onlyCalledFromThis 
    {   
        (address token, address depositor, uint256 amount) = abi.decode(requestPayload, (address,address,uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:]));
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }
            
            vault.updatePrincipleBalance(depositor, lastlyUpdatedPrincipleBalance);
        }

        emit DepositResult(success, token, depositor, amount);
    }

    function afterReceiveWithdrawPrincipleResponse(bytes memory requestPayload, bytes calldata responsePayload) 
        public 
        onlyCalledFromThis 
    {   
        (address token, address withdrawer, uint256 unlockPrincipleAmount) = abi.decode(requestPayload, (address,address,uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);
        uint256 lastlyUpdatedPrincipleBalance = uint256(bytes32(responsePayload[1:33]));
        if (success) {
            IVault vault = tokenVaults[token];
            if (address(vault) == address(0)) {
                revert VaultNotExist();
            }

            vault.updatePrincipleBalance(withdrawer, lastlyUpdatedPrincipleBalance);
            vault.updateWithdrawableBalance(withdrawer, unlockPrincipleAmount, 0);
        }

        emit WithdrawResult(success, token, withdrawer, unlockPrincipleAmount);
    }

    function afterReceiveDelegateResponse(bytes memory requestPayload, bytes calldata responsePayload) 
        public 
        onlyCalledFromThis 
    {   
        (address token, bytes32 operator, address delegator, uint256 amount) = abi.decode(requestPayload, (address,bytes32,address,uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit DelegateResult(success, delegator, operator, token, amount);
    }

    function afterReceiveUndelegateResponse(bytes memory requestPayload, bytes calldata responsePayload) 
        public 
        onlyCalledFromThis 
    {
        (address token, bytes32 operator, address undelegator, uint256 amount) = abi.decode(requestPayload, (address,bytes32,address,uint256));

        bool success = (uint8(bytes1(responsePayload[0])) == 1);

        emit UndelegateResult(success, undelegator, operator, token, amount);
    }
}