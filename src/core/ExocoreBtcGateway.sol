// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ASSETS_CONTRACT} from "../interfaces/precompiles/IAssets.sol";
import {CLAIM_REWARD_CONTRACT} from "../interfaces/precompiles/IClaimReward.sol";
import {DELEGATION_CONTRACT} from "../interfaces/precompiles/IDelegation.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {GatewayStorage} from "../storage/ExocoreGatewayStorage.sol";
contract ExocoreBtcGateway is Initializable, PausableUpgradeable, OwnableUpgradeable,GatewayStorage {

    uint32 internal CLIENT_CHAIN_ID;
    bytes public constant BTC_TOKEN = bytes("BTC");

    struct TxInfo {
        bool processed;
        uint256 timestamp;
    }

    mapping(bytes => TxInfo) public processedBtcTxs;
    mapping(bytes => bytes) public btcToExocoreAddress;
    mapping(bytes => bytes) public exocoreToBtcAddress;

    event DepositCompleted(bytes btcTxHash, bytes token, bytes depositor, uint256 amount, uint256 updatedBalance);
    event WithdrawPrincipalCompleted(bytes token, bytes withdrawer, uint256 amount, uint256 updatedBalance);
    event WithdrawRewardCompleted(bytes token, bytes withdrawer, uint256 amount, uint256 updatedBalance);
    event DelegationCompleted(bytes token, bytes delegator, bytes operator, uint256 amount);
    event UndelegationCompleted(bytes token, bytes delegator, bytes operator, uint256 amount);
    event DepositAndDelegationCompleted(
        bytes token, bytes depositor, bytes operator, uint256 amount, uint256 updatedBalance
    );
    event AddressRegistered(bytes btcAddress, bytes exocoreAddress);
    event ExocorePrecompileError(address precompileAddress);

    error UnauthorizedValidator();
    error RegisterClientChainToExocoreFailed(uint32 clientChainId);
    error ZeroAddressNotAllowed();
    error BtcTxAlreadyProcessed();
    error BtcAddressNotRegistered();
    error DepositFailed();
    error WithdrawPrincipalFailed();
    error WithdrawRewardFailed();
    error DelegationFailed();
    error UndelegationFailed();
    error EtherTransferFailed();

    modifier onlyAuthorizedValidator() {
        if (!_isAuthorizedValidator(msg.sender)) {
            revert UnauthorizedValidator();
        }
        _;
    }

    constructor(uint32 clientChainId) {
        _registerClientChain(clientChainId);
        _disableInitializers();
    }

    function initialize(address payable exocoreValidatorSetAddress_) external initializer {
        if (exocoreValidatorSetAddress_ == address(0)) {
            revert ZeroAddressNotAllowed();
        }

        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        __Ownable_init_unchained(exocoreValidatorSetAddress);
        __Pausable_init_unchained();
    }

    function pause() external {
        require(msg.sender == exocoreValidatorSetAddress, "Unauthorized");
        _pause();
    }

    function unpause() external {
        require(msg.sender == exocoreValidatorSetAddress, "Unauthorized");
        _unpause();
    }

    function _registerClientChain(uint32 clientChainId) internal {
        if (clientChainId == 0) {
            revert ZeroAddressNotAllowed();
        }
        if (!ASSETS_CONTRACT.registerClientChain(clientChainId)) {
            revert RegisterClientChainToExocoreFailed(clientChainId);
        }
        CLIENT_CHAIN_ID = clientChainId;
    }

    function deposit(bytes calldata btcTxHash, bytes calldata btcAddress, uint64 nonce, uint256 amount)
        external
        whenNotPaused
        onlyAuthorizedValidator
    {
        if (processedBtcTxs[btcTxHash].processed) {
            revert BtcTxAlreadyProcessed();
        }
        // verify nonce.
        bytes32 btcAddressBytes32 = _bytesToBytes32(btcAddress);
        _verifyAndUpdateNonce(CLIENT_CHAIN_ID, btcAddressBytes32, nonce);

        bytes memory exocoreAddress = btcToExocoreAddress[btcAddress];
        if (exocoreAddress.length == 0) {
            revert BtcAddressNotRegistered();
        }
        try ASSETS_CONTRACT.depositTo(0, BTC_TOKEN, exocoreAddress, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                revert DepositFailed();
            }
            processedBtcTxs[btcTxHash] = TxInfo(true, block.timestamp);
            emit DepositCompleted(btcTxHash, BTC_TOKEN, exocoreAddress, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed();
        }
    }

    function withdrawPrincipal(bytes calldata token, bytes calldata withdrawer, uint256 amount)
        external
        whenNotPaused
    {
        try ASSETS_CONTRACT.withdrawPrincipal(0, token, withdrawer, amount) returns (
            bool success, uint256 updatedBalance
        ) {
            if (!success) {
                revert WithdrawPrincipalFailed();
            }
            emit WithdrawPrincipalCompleted(token, withdrawer, amount, updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert WithdrawPrincipalFailed();
        }
    }

    function withdrawReward(bytes calldata token, bytes calldata withdrawer,uint256 amount) external whenNotPaused {
        try CLAIM_REWARD_CONTRACT.claimReward(CLIENT_CHAIN_ID,token, withdrawer,amount) returns (bool success, uint256 updatedBalance) {
            if (!success) {
                revert WithdrawRewardFailed();
            }
            emit WithdrawRewardCompleted(token, withdrawer, amount,updatedBalance);
        } catch {
            emit ExocorePrecompileError(address(CLAIM_REWARD_CONTRACT));
            revert WithdrawRewardFailed();
        }
    }

    function delegateTo(bytes calldata token, bytes calldata delegator, bytes calldata operator, uint256 amount)
        external
        whenNotPaused
    {
        try DELEGATION_CONTRACT.delegateTo(CLIENT_CHAIN_ID, token, delegator, operator, amount) returns (bool success) {
            if (!success) {
                revert DelegationFailed();
            }
            emit DelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert DelegationFailed();
        }
    }

    function undelegateFrom(bytes calldata token, bytes calldata delegator, bytes calldata operator, uint256 amount)
        external
        whenNotPaused
    {
        try DELEGATION_CONTRACT.undelegateFrom(CLIENT_CHAIN_ID, token, delegator, operator, amount) returns (bool success) {
            if (!success) {
                revert UndelegationFailed();
            }
            emit UndelegationCompleted(token, delegator, operator, amount);
        } catch {
            emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
            revert UndelegationFailed();
        }
    }

    function depositThenDelegateTo(
        bytes calldata token,
        bytes calldata depositor,
        bytes calldata operator,
        uint256 amount
    ) external whenNotPaused {
        try ASSETS_CONTRACT.depositTo(CLIENT_CHAIN_ID, token, depositor, amount) returns (bool depositSuccess, uint256 updatedBalance)
        {
            if (!depositSuccess) {
                revert DepositFailed();
            }

            try DELEGATION_CONTRACT.delegateTo(CLIENT_CHAIN_ID, token, depositor, operator, amount) returns (bool delegateSuccess) {
                if (!delegateSuccess) {
                    revert DelegationFailed();
                }
                emit DepositAndDelegationCompleted(token, depositor, operator, amount, updatedBalance);
            } catch {
                emit ExocorePrecompileError(address(DELEGATION_CONTRACT));
                revert DelegationFailed();
            }
        } catch {
            emit ExocorePrecompileError(address(ASSETS_CONTRACT));
            revert DepositFailed();
        }
    }

    function registerAddress(bytes calldata btcAddress, bytes calldata exocoreAddress) external {
        require(btcAddress.length > 0 && exocoreAddress.length > 0, "Invalid address");
        btcToExocoreAddress[btcAddress] = exocoreAddress;
        exocoreToBtcAddress[exocoreAddress] = btcAddress;
        emit AddressRegistered(btcAddress, exocoreAddress);
    }

    function getBtcAddress(bytes calldata exocoreAddress) external view returns (bytes memory) {
        return exocoreToBtcAddress[exocoreAddress];
    }

    function getCurrentNonce(uint16 srcChainId, bytes32 srcAddress) external view returns (uint64) {
        return inboundNonce[srcChainId][srcAddress];
    }

    function withdrawEther() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success,) = msg.sender.call{value: balance}("");
        if (!success) {
            revert EtherTransferFailed();
        }
    }

    receive() external payable {}

    fallback() external payable {}

    // This function needs to be implemented
    function _isAuthorizedValidator(address validator) internal view returns (bool) {
        // Implementation depends on how you determine if a validator is authorized
        // For example, you might check against a list of authorized validators
        // or query another contract
        return validator == exocoreValidatorSetAddress;
    }

    function _bytesToBytes32(bytes memory source) internal pure returns (bytes32 result) {
        if (source.length == 0) {
            return 0x0;
        }
        assembly {
            result := mload(add(source, 32))
        }
    }


}
