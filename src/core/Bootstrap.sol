// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
// Do not use IERC20 because it does not expose the decimals() function.
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";

// This import is used for @inheritdoc but slither does not recognize it.
// slither-disable-next-line unused-import
import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";
import {ICustomProxyAdmin} from "../interfaces/ICustomProxyAdmin.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IValidatorRegistry} from "../interfaces/IValidatorRegistry.sol";

import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";
import {IVault} from "../interfaces/IVault.sol";

import {Errors} from "../libraries/Errors.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";
import {BootstrapLzReceiver} from "./BootstrapLzReceiver.sol";

/// @title Bootstrap
/// @author ExocoreNetwork
/// @notice This contract is used to Bootstrap the Exocore network. It accepts validator registration, deposits and
/// delegations.
contract Bootstrap is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    ITokenWhitelister,
    ILSTRestakingController,
    IValidatorRegistry,
    BootstrapLzReceiver
{

    /// @notice Constructor for the Bootstrap contract.
    /// @param endpoint_ The address of the LayerZero endpoint contract.
    /// @param exocoreChainId_ The chain ID of the Exocore chain.
    /// @param vaultBeacon_ The address of the beacon contract for the vault.
    /// @param beaconProxyBytecode_ The address of the beacon proxy bytecode contract.
    constructor(address endpoint_, uint32 exocoreChainId_, address vaultBeacon_, address beaconProxyBytecode_)
        OAppCoreUpgradeable(endpoint_)
        BootstrapStorage(exocoreChainId_, vaultBeacon_, beaconProxyBytecode_)
    {
        _disableInitializers();
    }

    /// @notice Initializes the Bootstrap contract.
    /// @param owner The address of the contract owner.
    /// @param spawnTime_ The spawn time of the Exocore chain.
    /// @param offsetDuration_ The offset duration before the spawn time.
    /// @param whitelistTokens_ The list of whitelisted tokens.
    /// @param customProxyAdmin_ The address of the custom proxy admin.
    function initialize(
        address owner,
        uint256 spawnTime_,
        uint256 offsetDuration_,
        address[] calldata whitelistTokens_,
        address customProxyAdmin_
    ) external initializer {
        if (owner == address(0)) {
            revert Errors.ZeroAddress();
        }

        _validateSpawnTimeAndOffsetDuration(spawnTime_, offsetDuration_);
        spawnTime = spawnTime_;
        offsetDuration = offsetDuration_;

        if (customProxyAdmin_ == address(0)) {
            revert Errors.ZeroAddress();
        }

        _addWhitelistTokens(whitelistTokens_);

        _whiteListFunctionSelectors[Action.REQUEST_MARK_BOOTSTRAP] = this.markBootstrapped.selector;

        customProxyAdmin = customProxyAdmin_;
        bootstrapped = false;

        // msg.sender is not the proxy admin but the transparent proxy itself, and hence,
        // cannot be used here. we must require a separate owner. since the Exocore validator
        // set can not sign without the chain, the owner is likely to be an EOA or a
        // contract controlled by one.
        _transferOwnership(owner);
        __Pausable_init_unchained();
        __ReentrancyGuard_init_unchained();
    }

    /// @notice Checks if the contract is locked, meaning it has passed the offset duration
    /// before the Exocore spawn time.
    /// @dev Returns true if the contract is locked, false otherwise.
    /// @return bool Returns `true` if the contract is locked, `false` otherwise.
    function isLocked() public view returns (bool) {
        return block.timestamp >= spawnTime - offsetDuration;
    }

    /// @dev Modifier to restrict operations based on the contract's defined timeline, that is,
    /// during the offset duration before the Exocore spawn time.
    modifier beforeLocked() {
        if (isLocked()) {
            revert Errors.BootstrapBeforeLocked();
        }
        _;
    }

    /// @notice Pauses the contract.
    /// @dev Pausing is not gated by the beforeLocked modifier.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract.
    /// @dev Unpausing is not gated by the beforeLocked modifier.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Allows the contract owner to modify the spawn time of the Exocore chain.
    /// @dev This function can only be called by the contract owner and must
    /// be called before the currently set lock time has started.
    /// @param spawnTime_ The new spawn time in seconds.
    function setSpawnTime(uint256 spawnTime_) external onlyOwner beforeLocked {
        _validateSpawnTimeAndOffsetDuration(spawnTime_, offsetDuration);
        // technically the spawn time can be moved backwards in time as well.
        spawnTime = spawnTime_;
        emit SpawnTimeUpdated(spawnTime);
    }

    /// @notice Allows the contract owner to modify the offset duration that determines
    /// the lock period before the Exocore spawn time.
    /// @dev This function can only be called by the contract owner and must be called
    /// before the currently set lock time has started.
    /// @param offsetDuration_ The new offset duration in seconds.
    function setOffsetDuration(uint256 offsetDuration_) external onlyOwner beforeLocked {
        _validateSpawnTimeAndOffsetDuration(spawnTime, offsetDuration_);
        offsetDuration = offsetDuration_;
        emit OffsetDurationUpdated(offsetDuration);
    }

    /// @dev Validates the spawn time and offset duration.
    ///      The spawn time must be in the future and greater than the offset duration.
    ///      The difference of the two must be greater than the current time.
    /// @param spawnTime_ The spawn time of the Exocore chain to validate.
    /// @param offsetDuration_ The offset duration before the spawn time to validate.
    function _validateSpawnTimeAndOffsetDuration(uint256 spawnTime_, uint256 offsetDuration_) internal view {
        if (offsetDuration_ == 0) {
            revert Errors.ZeroValue();
        }
        // spawnTime_ == 0 is included in the below check, since the timestamp
        // is always greater than 0. the spawn time must not be equal to the
        // present time either, although, when marking as bootstrapped, we do
        // allow that case intentionally.
        if (block.timestamp > spawnTime_) {
            revert Errors.BootstrapSpawnTimeAlreadyPast();
        }
        // guard against underflow of lockTime calculation
        if (offsetDuration_ > spawnTime_) {
            revert Errors.BootstrapSpawnTimeLessThanDuration();
        }
        uint256 lockTime = spawnTime_ - offsetDuration_;
        if (block.timestamp >= lockTime) {
            revert Errors.BootstrapLockTimeAlreadyPast();
        }
    }

    /// @inheritdoc ITokenWhitelister
    function addWhitelistTokens(address[] calldata tokens) external beforeLocked onlyOwner whenNotPaused {
        _addWhitelistTokens(tokens);
    }

    /// @dev The internal function to add tokens to the whitelist.
    /// @param tokens The list of token addresses to be added to the whitelist.
    // Though `_deployVault` would make external call to newly created `Vault` contract and initialize it,
    // `Vault` contract belongs to Exocore and we could make sure its implementation does not have dangerous behavior
    // like reentrancy.
    // slither-disable-next-line reentrancy-no-eth
    function _addWhitelistTokens(address[] calldata tokens) internal {
        for (uint256 i = 0; i < tokens.length; ++i) {
            address token = tokens[i];
            if (token == address(0)) {
                revert Errors.ZeroAddress();
            }
            if (isWhitelistedToken[token]) {
                revert Errors.BootstrapAlreadyWhitelisted(token);
            }

            whitelistTokens.push(token);
            isWhitelistedToken[token] = true;

            // deploy the corresponding vault if not deployed before
            if (address(tokenToVault[token]) == address(0)) {
                _deployVault(token);
            }

            emit WhitelistTokenAdded(token);
        }
    }

    /// @inheritdoc ITokenWhitelister
    function getWhitelistedTokensCount() external view returns (uint256) {
        return whitelistTokens.length;
    }

    /// @inheritdoc IValidatorRegistry
    function registerValidator(
        string calldata validatorAddress,
        string calldata name,
        Commission memory commission,
        bytes32 consensusPublicKey
    ) external beforeLocked whenNotPaused isValidBech32Address(validatorAddress) {
        // ensure that there is only one validator per ethereum address
        if (bytes(ethToExocoreAddress[msg.sender]).length > 0) {
            revert Errors.BootstrapValidatorAlreadyHasAddress(msg.sender);
        }
        // check if validator with the same exocore address already exists
        if (bytes(validators[validatorAddress].name).length > 0) {
            revert Errors.BootstrapValidatorAlreadyRegistered();
        }
        _validateConsensusKey(consensusPublicKey);
        // and that the name (meta info) is non-empty and unique.
        if (bytes(name).length == 0) {
            revert Errors.BootstrapValidatorNameLengthZero();
        }
        if (validatorNameInUse[name]) {
            revert Errors.BootstrapValidatorNameAlreadyUsed();
        }
        // check that the commission is valid.
        if (!isCommissionValid(commission)) {
            revert Errors.BootstrapInvalidCommission();
        }
        ethToExocoreAddress[msg.sender] = validatorAddress;
        validators[validatorAddress] =
            IValidatorRegistry.Validator({name: name, commission: commission, consensusPublicKey: consensusPublicKey});
        registeredValidators.push(msg.sender);
        consensusPublicKeyInUse[consensusPublicKey] = true;
        validatorNameInUse[name] = true;
        emit ValidatorRegistered(msg.sender, validatorAddress, name, commission, consensusPublicKey);
    }

    /// @notice Checks if the provided commission is valid.
    /// @dev The commission's rates must be <= 1e18 (100%) and the rate must be <= maxRate and maxChangeRate.
    /// @param commission The commission to check.
    /// @return bool Returns `true` if the commission is valid, `false` otherwise.
    // forgefmt: disable-next-item
    function isCommissionValid(Commission memory commission) public pure returns (bool) {
        return commission.rate <= 1e18 &&
               commission.maxRate <= 1e18 &&
               commission.maxChangeRate <= 1e18 &&
               commission.rate <= commission.maxRate &&
               commission.maxChangeRate <= commission.maxRate;
    }

    /// @inheritdoc IValidatorRegistry
    function replaceKey(bytes32 newKey) external beforeLocked whenNotPaused {
        if (bytes(ethToExocoreAddress[msg.sender]).length == 0) {
            revert Errors.BootstrapValidatorNotExist();
        }
        _validateConsensusKey(newKey);
        bytes32 oldKey = validators[ethToExocoreAddress[msg.sender]].consensusPublicKey;
        consensusPublicKeyInUse[oldKey] = false;
        consensusPublicKeyInUse[newKey] = true;
        validators[ethToExocoreAddress[msg.sender]].consensusPublicKey = newKey;
        emit ValidatorKeyReplaced(ethToExocoreAddress[msg.sender], newKey);
    }

    /// @inheritdoc IValidatorRegistry
    function updateRate(uint256 newRate) external beforeLocked whenNotPaused {
        string memory validatorAddress = ethToExocoreAddress[msg.sender];
        if (bytes(validatorAddress).length == 0) {
            revert Errors.BootstrapValidatorNotExist();
        }
        // across the lifetime of this contract before network bootstrap,
        // allow the editing of commission only once.
        if (commissionEdited[validatorAddress]) {
            revert Errors.BootstrapComissionAlreadyEdited();
        }
        Commission memory commission = validators[validatorAddress].commission;
        uint256 rate = commission.rate;
        uint256 maxRate = commission.maxRate;
        uint256 maxChangeRate = commission.maxChangeRate;
        // newRate <= maxRate <= 1e18
        if (newRate > maxRate) {
            revert Errors.BootstrapRateExceedsMaxRate();
        }
        // to prevent validators from blindsiding users by first registering at low rate and
        // subsequently increasing it, we should also check that the change is within the
        // allowed rate change.
        if (newRate > rate + maxChangeRate) {
            revert Errors.BootstrapRateChangeExceedsMaxChangeRate();
        }
        validators[validatorAddress].commission.rate = newRate;
        commissionEdited[validatorAddress] = true;
        emit ValidatorCommissionUpdated(newRate);
    }

    /// @notice Validates a consensus key.
    /// @dev The validation checks include non-empty key and uniqueness.
    /// @param key The consensus key to validate.
    function _validateConsensusKey(bytes32 key) internal view {
        // check that the consensus key is not empty.
        if (key == bytes32(0)) {
            revert Errors.ZeroValue();
        }
        // check that the consensus key is unique.
        if (consensusPublicKeyInUse[key]) {
            revert Errors.BootstrapConsensusPubkeyAlreadyUsed(key);
        }
    }

    /// @inheritdoc ILSTRestakingController
    function deposit(address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        nonReentrant // interacts with Vault
    {
        _deposit(msg.sender, token, amount);
    }

    /// @dev Internal version of deposit.
    /// @param depositor The address of the depositor.
    /// @param token The address of the token.
    /// @param amount The amount of the @param token to deposit.
    function _deposit(address depositor, address token, uint256 amount) internal {
        IVault vault = _getVault(token);
        vault.deposit(depositor, amount);

        if (!isDepositor[depositor]) {
            isDepositor[depositor] = true;
            depositors.push(depositor);
        }

        // staker_asset.go duplicate here. the duplication is required (and not simply inferred
        // from vault) because the vault is not altered by the gateway in response to
        // delegations or undelegations. hence, this is not something we can do either.
        totalDepositAmounts[depositor][token] += amount;
        withdrawableAmounts[depositor][token] += amount;
        depositsByToken[token] += amount;

        // afterReceiveDepositResponse stores the TotalDepositAmount in the principal.
        vault.updatePrincipalBalance(depositor, totalDepositAmounts[depositor][token]);

        emit DepositResult(true, token, depositor, amount);
    }

    /// @inheritdoc ILSTRestakingController
    function withdrawPrincipalFromExocore(address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        nonReentrant // interacts with Vault
    {
        _withdraw(msg.sender, token, amount);
    }

    /// @dev Internal version of withdraw.
    /// @param user The address of the withdrawer.
    /// @param token The address of the token.
    /// @param amount The amount of the @param token to withdraw.
    function _withdraw(address user, address token, uint256 amount) internal {
        IVault vault = _getVault(token);

        uint256 deposited = totalDepositAmounts[user][token];
        if (deposited < amount) {
            revert Errors.BootstrapInsufficientDepositedBalance();
        }
        uint256 withdrawable = withdrawableAmounts[user][token];
        if (withdrawable < amount) {
            revert Errors.BootstrapInsufficientWithdrawableBalance();
        }

        // when the withdraw precompile is called, it does these things.
        totalDepositAmounts[user][token] -= amount;
        withdrawableAmounts[user][token] -= amount;
        depositsByToken[token] -= amount;

        // afterReceiveWithdrawPrincipalResponse
        vault.updatePrincipalBalance(user, totalDepositAmounts[user][token]);
        vault.updateWithdrawableBalance(user, amount, 0);

        emit WithdrawPrincipalResult(true, token, user, amount);
    }

    /// @inheritdoc ILSTRestakingController
    /// @dev This is not yet supported.
    function withdrawRewardFromExocore(address, uint256) external payable override beforeLocked whenNotPaused {
        revert NotYetSupported();
    }

    /// @inheritdoc IBaseRestakingController
    function claim(address token, uint256 amount, address recipient)
        external
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        nonReentrant // because it interacts with vault
    {
        IVault vault = _getVault(token);
        vault.withdraw(msg.sender, recipient, amount);
    }

    /// @inheritdoc IBaseRestakingController
    function delegateTo(string calldata validator, address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(validator)
    // does not need a reentrancy guard
    {
        _delegateTo(msg.sender, validator, token, amount);
    }

    /// @dev The internal version of `delegateTo`.
    /// @param user The address of the delegator.
    /// @param validator The address of the validator.
    /// @param token The address of the token.
    /// @param amount The amount of the @param token to delegate.
    function _delegateTo(address user, string calldata validator, address token, uint256 amount) internal {
        if (msg.value > 0) {
            revert Errors.BootstrapNoEtherForDelegation();
        }
        // check that validator is registered
        if (bytes(validators[validator].name).length == 0) {
            revert Errors.BootstrapValidatorNotExist();
        }
        // validator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 withdrawable = withdrawableAmounts[user][token];
        if (withdrawable < amount) {
            revert Errors.BootstrapInsufficientWithdrawableBalance();
        }
        delegations[user][validator][token] += amount;
        delegationsByValidator[validator][token] += amount;
        withdrawableAmounts[user][token] -= amount;

        emit DelegateResult(true, user, validator, token, amount);
    }

    /// @inheritdoc IBaseRestakingController
    function undelegateFrom(string calldata validator, address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(validator)
    // does not need a reentrancy guard
    {
        _undelegateFrom(msg.sender, validator, token, amount);
    }

    /// @dev The internal version of `undelegateFrom`.
    /// @param user The address of the delegator.
    /// @param validator The address of the validator.
    /// @param token The address of the token.
    /// @param amount The amount of the @param token to undelegate.
    function _undelegateFrom(address user, string calldata validator, address token, uint256 amount) internal {
        if (msg.value > 0) {
            revert Errors.BootstrapNoEtherForDelegation();
        }
        // check that validator is registered
        if (bytes(validators[validator].name).length == 0) {
            revert Errors.BootstrapValidatorNotExist();
        }
        // validator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 delegated = delegations[user][validator][token];
        if (delegated < amount) {
            revert Errors.BootstrapInsufficientDelegatedBalance();
        }
        // the undelegation is released immediately since it is not at stake yet.
        delegations[user][validator][token] -= amount;
        delegationsByValidator[validator][token] -= amount;
        withdrawableAmounts[user][token] += amount;

        emit UndelegateResult(true, user, validator, token, amount);
    }

    /// @inheritdoc ILSTRestakingController
    // Though `_deposit` would make external call to `Vault` and some state variables would be written in the following
    // `_delegateTo`,
    // `Vault` contract belongs to Exocore and we could make sure it's implementation does not have dangerous behavior
    // like reentrancy.
    // slither-disable-next-line reentrancy-no-eth
    function depositThenDelegateTo(address token, uint256 amount, string calldata validator)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(validator)
        nonReentrant // because it interacts with vault in deposit
    {
        _deposit(msg.sender, token, amount);
        _delegateTo(msg.sender, validator, token, amount);
    }

    /// @notice Marks the contract as bootstrapped.
    /// @dev A contract can be marked as bootstrapped only when the current time is more than
    /// the Exocore spawn time, since such a call must originate from the Exocore chain. To mark
    /// a contract as bootstrapped, the address of the client chain gateway logic contract and its
    /// initialization data must be set. The contract must not have been bootstrapped before.
    /// Once it is marked bootstrapped, the implementation of the contract is upgraded to the
    /// client chain gateway logic contract.
    function markBootstrapped() public onlyCalledFromThis whenNotPaused {
        // whenNotPaused is applied so that the upgrade does not proceed without unpausing it.
        // LZ checks made so far include:
        // lzReceive called by endpoint
        // correct address on remote (peer match)
        // chainId match
        // nonce match, which requires that inbound nonce is uint64(1).
        // TSS checks are not super clear since they can be set by anyone
        // but at this point that does not matter since it is not fully implemented anyway.
        if (block.timestamp < spawnTime) {
            revert Errors.BootstrapNotSpawnTime();
        }
        if (bootstrapped) {
            revert Errors.BootstrapAlreadyBootstrapped();
        }
        if (clientChainGatewayLogic == address(0)) {
            revert Errors.ZeroAddress();
        }
        ICustomProxyAdmin(customProxyAdmin).changeImplementation(
            // address(this) is storage address and not logic address. so it is a proxy.
            ITransparentUpgradeableProxy(address(this)),
            clientChainGatewayLogic,
            clientChainInitializationData
        );
        emit Bootstrapped();
    }

    /// @notice Sets a new client chain gateway logic and its initialization data.
    /// @dev Allows the contract owner to update the address and initialization data for the
    /// client chain gateway logic. The change can only occur prior to bootstrapping.
    /// @param _clientChainGatewayLogic The address of the new client chain gateway logic
    /// contract.
    /// @param _clientChainInitializationData The initialization data to be used when setting up
    /// the new logic contract.
    function setClientChainGatewayLogic(address _clientChainGatewayLogic, bytes calldata _clientChainInitializationData)
        public
        onlyOwner
    {
        if (_clientChainGatewayLogic == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (_clientChainInitializationData.length < 4) {
            revert Errors.BootstrapClientChainDataMalformed();
        }
        clientChainGatewayLogic = _clientChainGatewayLogic;
        clientChainInitializationData = _clientChainInitializationData;
        emit ClientChainGatewayLogicUpdated(_clientChainGatewayLogic, _clientChainInitializationData);
    }

    /// @dev Gets the count of registered validators.
    /// @return The number of registered validators.
    /// @notice This function returns the total number of registered validators in the contract.
    function getValidatorsCount() external view returns (uint256) {
        return registeredValidators.length;
    }

    /// @dev Gets the count of depositors.
    /// @return The number of depositors.
    /// @notice This function returns the total number of depositors in the contract.
    function getDepositorsCount() external view returns (uint256) {
        return depositors.length;
    }

    /// @notice Retrieves information for a supported token by its index in the storage array.
    /// @dev Returns comprehensive details about a token, including its ERC20 attributes and deposit amount.
    /// This function only exists in the Bootstrap contract and not in the ClientChainGateway, which
    /// does not track the deposits of whitelisted tokens.
    /// @param index The index of the token in the `supportedTokens` array.
    /// @return A `TokenInfo` struct containing the token's name, symbol, address, decimals, total supply, and deposit
    /// amount.
    function getWhitelistedTokenAtIndex(uint256 index) public view returns (TokenInfo memory) {
        if (index >= whitelistTokens.length) {
            revert Errors.IndexOutOfBounds();
        }
        address tokenAddress = whitelistTokens[index];
        ERC20 token = ERC20(tokenAddress);
        return TokenInfo({
            name: token.name(),
            symbol: token.symbol(),
            tokenAddress: tokenAddress,
            decimals: token.decimals(),
            totalSupply: token.totalSupply(),
            depositAmount: depositsByToken[tokenAddress]
        });
    }

}
