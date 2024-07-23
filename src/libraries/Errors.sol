pragma solidity ^0.8.19;

/// @title Errors library
/// @notice A library for all errors that can be thrown in the Exocore contracts
/// All errors in Exocore follow the following syntax: 'error ContractNameErrorName(arg1, arg2, ...)', where
/// 'ContractName' is the name of the contract
/// that the error originates from and 'ErrorName' is the name of the error. The arguments are optional and are used to
/// provide additional context to the error
/// 'Global' errors are those that are thrown from various contracts throughout the protocol and do not have a
/// 'ContractName' prefix

library Errors {

    /////////////////////
    //  Global Errors  //
    /////////////////////

    error AlreadySet();

    /**
     * The passed-in address is the zero address, i.e. address(0)
     */
    error ZeroAddress();

    /**
     * The passed-in amount is zero
     */
    error ZeroAmount();

    /**
     * The passed-in value is zero - used for bytes32
     */
    error ZeroValue();

    /**
     * Index out of array bounds
     */
    error IndexOutOfBounds();

    ////////////////////////
    //  Bootstrap Errors  //
    ////////////////////////

    /**
     * Bootstrap: spawn time should be in the future
     */
    error BootstrapSpawnTimeAlreadyPast();

    /**
     * Bootstrap: spawn time should be greater than offset duration
     */
    error BootstrapSpawnTimeLessThanDuration();

    /**
     * Bootstrap: lock time should be in the future
     */
    error BootstrapLockTimeAlreadyPast();

    /**
     * Bootstrap: operation not allowed after lock time
     */
    error BootstrapBeforeLocked();

    /**
     * Bootstrap: token should be not whitelisted before
     */
    error BootstrapAlreadyWhitelisted(address token);

    /**
     * Bootstrap: Ethereum address already linked to a validator
     */
    error BootstrapValidatorAlreadyHasAddress(address validator);

    /**
     * Bootstrap: Validator with this Exocore address is already registered
     */
    error BootstrapValidatorAlreadyRegistered();

    /**
     * Bootstrap: Consensus public key already in use
     */
    error BootstrapConsensusPubkeyAlreadyUsed(bytes32 publicKey);

    /**
     * Bootstrap: Validator name already in use
     */
    error BootstrapValidatorNameAlreadyUsed();

    /**
     * Bootstrap: Invalid commission
     */
    error BootstrapInvalidCommission();

    /**
     * Bootstrap: validator does not exist
     */
    error BootstrapValidatorNotExist();

    /**
     * Bootstrap: Commission already edited once
     */
    error BootstrapComissionAlreadyEdited();

    /**
     * Bootstrap: Rate exceeds max rate
     */
    error BootstrapRateExceedsMaxRate();

    /**
     * Bootstrap: Rate change exceeds max change rate
     */
    error BootstrapRateChangeExceedsMaxChangeRate();

    /**
     * Bootstrap: insufficient deposited balance
     */
    error BootstrapInsufficientDepositedBalance();

    /**
     * Bootstrap: insufficient withdrawable balance
     */
    error BootstrapInsufficientWithdrawableBalance();

    /**
     * Bootstrap: insufficient delegated balance
     */
    error BootstrapInsufficientDelegatedBalance();

    /**
     * Bootstrap: no ether required for delegation/undelegation
     */
    error BootstrapNoEtherForDelegation();

    /**
     * Bootstrap: not yet in the bootstrap time
     */
    error BootstrapNotSpawnTime();

    /**
     * Bootstrap: not yet bootstrapped
     */
    error BootstrapAlreadyBootstrapped();

    /**
     * Bootstrap: client chain initialization data is malformed
     */
    error BootstrapClientChainDataMalformed();

    //////////////////////////////////
    //  BootstrapLzReceiver Errors  //
    //////////////////////////////////

    /**
     * BootstrapLzReceiver: could only be called from this contract itself with low level call
     */
    error BootstrapLzReceiverOnlyCalledFromThis();

    /**
     * BootstrapLzReceiver: invalid action
     */
    error BootstrapLzReceiverInvalidAction();

    /////////////////////////////////
    //  ClientChainGateway Errors  //
    /////////////////////////////////

    /**
     * ClientChainGateway: caller is not Exocore validator set aggregated address
     */
    error ClientChainGatewayInvalidCaller();

    /**
     * ClientChainGateway: tokens length should not execeed 255
     */
    error ClientChainGatewayAddWhitelistTooManyTokens();

    /**
     * ClientChainGateway: token should not be whitelisted before
     */
    error ClientChainGatewayAlreadyWhitelisted();

    //////////////////////////////////////
    //  ClientGatewayLzReceiver Errors  //
    //////////////////////////////////////

    /**
     * ClientChainLzReceiver: could only be called from this contract itself with low level call
     */
    error ClientGatewayLzReceiverOnlyCalledFromThis();

    ///////////////////////////////
    //  CustomProxyAdmin Errors  //
    ///////////////////////////////

    /**
     * CustomProxyAdmin: sender must be bootstrapper
     */
    error CustomProxyAdminOnlyCalledFromBootstrapper();

    /**
     * CustomProxyAdmin: sender must be the proxy itself
     */
    error CustomProxyAdminOnlyCalledFromProxy();

    /////////////////////////
    //  ExoCapsule Errors  //
    /////////////////////////

    /**
     * ExoCapsule: withdrawal amount is larger than staker's withdrawable balance
     */
    error ExoCapsuleWithdrawalAmountExceeds();

    /**
     * ExoCapsule: withdrawNonBeaconChainETHBalance: amountToWithdraw is greater than nonBeaconChainETHBalance
     */
    error ExoCapsuleNonBeaconChainWithdrawalAmountExceeds();

    /**
     * ExoCapsule: timestamp should be greater than beacon chain genesis timestamp
     */
    error ExoCapsuleTimestampBeforeGenesis();

    /////////////////////////////
    //  ExocoreGateway Errors  //
    /////////////////////////////

    /**
     * ExocoreGateway: can only be called from this contract itself with a low-level call
     */
    error ExocoreGatewayOnlyCalledFromThis();

    /**
     * ExocoreGateway: caller is not Exocore validator set aggregated address
     */
    error ExocoreGatewayInvalidCaller();

    /**
     * ExocoreGateway: failed to get client chain ids
     */
    error ExocoreGatewayFailedToGetClientChainIds();

    /**
     * ExocoreGateway: failed to decode client chain ids
     */
    error ExocoreGatewayFailedToDecodeClientChainIds();
    /**
     * ExocoreGateway: client chain should be registered before setting peer to change peer address
     */
    error ExocoreGatewayNotRegisteredClientChainId();

    ////////////////////////////////////////
    //  NativeRestakingController Errors  //
    ////////////////////////////////////////

    /**
     * NativeRestakingController: native restaking is not enabled
     */
    error NativeRestakingControllerNotWhitelisted();

    /**
     * NativeRestakingController: stake value must be exactly 32 ether
     */
    error NativeRestakingControllerInvalidStakeValue();

    /**
     * NativeRestakingController: message sender has already created the capsule
     */
    error NativeRestakingControllerCapsuleAlreadyCreated();

    ////////////////////
    //  Vault Errors  //
    ////////////////////

    /**
     * Vault: caller is not the gateway
     */
    error VaultCallerIsNotGateway();

    /**
     * Vault: withdrawal amount is larger than depositor's withdrawable balance
     */
    error VaultWithdrawalAmountExceeds();

    /**
     * Vault: total principal unlock amount is larger than the total deposited amount
     */
    error VaultPrincipalExceedsTotalDeposit();

    /**
     * Vault: total principal unlock amount is larger than the total deposited amount
     */
    error VaultTotalUnlockPrincipalExceedsDeposit();

}
