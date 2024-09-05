// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @dev @title Errors library
/// @dev @notice A library for all errors that can be thrown in the Exocore contracts
/// @dev All errors in Exocore follow the following syntax: 'error ContractNameErrorName(arg1, arg2, ...)', where
/// @dev 'ContractName' is the name of the contract
/// @dev that the error originates from and 'ErrorName' is the name of the error. The arguments are optional and are
/// used to
/// @dev provide additional context to the error
/// @dev 'Global' errors are those that are thrown from various contracts throughout the protocol and do not have a
/// @dev 'ContractName' prefix

library Errors {

    /////////////////////
    //  Global Errors  //
    /////////////////////

    /// @dev Thrown when the passed-in address is the zero address, i.e. address(0)
    error ZeroAddress();

    /// @dev Thrown when passed-in amount is zero
    error ZeroAmount();

    /// @dev Thrown when the passed-in msg.value is not zero but should be
    error NonZeroValue();

    /// @dev Thrown when the passed-in msg.value is zero but should not be
    error ZeroValue();

    /// @dev Index out of array bounds
    error IndexOutOfBounds();

    ////////////////////////
    //  Bootstrap Errors  //
    ////////////////////////

    /// @dev Bootstrap: spawn time should be in the future
    error BootstrapSpawnTimeAlreadyPast();

    /// @dev Bootstrap: spawn time should be greater than offset duration
    error BootstrapSpawnTimeLessThanDuration();

    /// @dev Bootstrap: lock time should be in the future
    error BootstrapLockTimeAlreadyPast();

    /// @dev Bootstrap: operation not allowed after lock time
    error BootstrapBeforeLocked();

    /// @dev Bootstrap: token should be not whitelisted before
    /// @param token The address of the token already whitelisted
    error BootstrapAlreadyWhitelisted(address token);

    /// @dev Bootstrap: Ethereum address already linked to a validator
    /// @param validator The Ethereum address of the validator
    error BootstrapValidatorAlreadyHasAddress(address validator);

    /// @dev Bootstrap: Validator with this Exocore address is already registered
    error BootstrapValidatorAlreadyRegistered();

    /// @dev Bootstrap: Consensus public key already in use
    /// @param publicKey The public key that is already in use
    error BootstrapConsensusPubkeyAlreadyUsed(bytes32 publicKey);

    /// @dev Bootstrap: Validator name already in use
    error BootstrapValidatorNameAlreadyUsed();

    /// @dev Bootstrap: Invalid commission
    error BootstrapInvalidCommission();

    /// @dev Bootstrap: validator does not exist
    error BootstrapValidatorNotExist();

    /// @dev Bootstrap: Commission already edited once
    error BootstrapComissionAlreadyEdited();

    /// @dev Bootstrap: Rate exceeds max rate
    error BootstrapRateExceedsMaxRate();

    /// @dev Bootstrap: Rate change exceeds max change rate
    error BootstrapRateChangeExceedsMaxChangeRate();

    /// @dev Bootstrap: insufficient deposited balance
    error BootstrapInsufficientDepositedBalance();

    /// @dev Bootstrap: insufficient withdrawable balance
    error BootstrapInsufficientWithdrawableBalance();

    /// @dev Bootstrap: insufficient delegated balance
    error BootstrapInsufficientDelegatedBalance();

    /// @dev Bootstrap: no ether required for delegation/undelegation
    error BootstrapNoEtherForDelegation();

    /// @dev Bootstrap: client chain initialization data is malformed
    error BootstrapClientChainDataMalformed();

    /// @dev Bootstrap: validator name length is zero
    error BootstrapValidatorNameLengthZero();

    //////////////////////////////////
    //  BootstrapLzReceiver Errors  //
    //////////////////////////////////

    /// @dev BootstrapLzReceiver: could only be called from this contract itself with low level call
    error BootstrapLzReceiverOnlyCalledFromThis();

    /// @dev BootstrapLzReceiver: invalid action
    error BootstrapLzReceiverInvalidAction();

    /////////////////////////////////
    //  ClientChainGateway Errors  //
    /////////////////////////////////

    /// @dev ClientChainGateway: tokens length should not execeed 255
    error ClientChainGatewayAddWhitelistTooManyTokens();

    /// @dev ClientChainGateway: token should not be whitelisted before
    error ClientChainGatewayAlreadyWhitelisted(address token);

    //////////////////////////////////////
    //  ClientGatewayLzReceiver Errors  //
    //////////////////////////////////////

    /// @dev ClientChainLzReceiver: could only be called from this contract itself with low level call
    error ClientGatewayLzReceiverOnlyCalledFromThis();

    ///////////////////////////////
    //  CustomProxyAdmin Errors  //
    ///////////////////////////////

    /// @dev CustomProxyAdmin: sender must be bootstrapper
    error CustomProxyAdminOnlyCalledFromBootstrapper();

    /// @dev CustomProxyAdmin: sender must be the proxy itself
    error CustomProxyAdminOnlyCalledFromProxy();

    /////////////////////////
    //  ExoCapsule Errors  //
    /////////////////////////

    /// @dev ExoCapsule: withdrawal amount is larger than staker's withdrawable balance
    error ExoCapsuleWithdrawalAmountExceeds();

    /// @dev ExoCapsule: withdrawNonBeaconChainETHBalance: amountToWithdraw is greater than nonBeaconChainETHBalance
    error ExoCapsuleNonBeaconChainWithdrawalAmountExceeds();

    /// @dev ExoCapsule: timestamp should be greater than beacon chain genesis timestamp
    error ExoCapsuleTimestampBeforeGenesis();

    /////////////////////////////
    //  ExocoreGateway Errors  //
    /////////////////////////////

    /// @dev ExocoreGateway: can only be called from this contract itself with a low-level call
    error ExocoreGatewayOnlyCalledFromThis();

    /// @dev ExocoreGateway: failed to get client chain ids
    error ExocoreGatewayFailedToGetClientChainIds();

    /// @dev ExocoreGateway: client chain should be registered before.
    error ExocoreGatewayNotRegisteredClientChainId();

    /// @dev ExocoreGateway: failed to check if the client id is registered
    error ExocoreGatewayFailedToCheckClientChainId();

    /// @dev ExocoreGateway: thrown when associateOperatorWithEVMStaker failed
    error AssociateOperatorFailed(uint32 clientChainId, address staker, string operator);

    /// @dev thrown when dissociateOperatorFromEVMStaker failed
    error DissociateOperatorFailed(uint32 clientChainId, address staker);

    ////////////////////////////////////////
    //  NativeRestakingController Errors  //
    ////////////////////////////////////////

    /// @dev NativeRestakingController: native restaking is not enabled
    error NativeRestakingControllerNotWhitelisted();

    /// @dev NativeRestakingController: stake value must be exactly 32 ether
    error NativeRestakingControllerInvalidStakeValue();

    /// @dev NativeRestakingController: message sender has already created the capsule
    error NativeRestakingControllerCapsuleAlreadyCreated();

    ////////////////////
    //  Vault Errors  //
    ////////////////////

    /// @dev Vault: caller is not the gateway
    error VaultCallerIsNotGateway();

    /// @dev Vault: withdrawal amount is larger than depositor's withdrawable balance
    error VaultWithdrawalAmountExceeds();

    /// @dev Vault: total principal unlock amount is larger than the total deposited amount
    error VaultPrincipalExceedsTotalDeposit();

    /// @dev Vault: total principal unlock amount is larger than the total deposited amount
    error VaultTotalUnlockPrincipalExceedsDeposit();

    /// @dev Vault: forbid to deploy vault for the virtual token address representing natively staked ETH
    error ForbidToDeployVault();

}
