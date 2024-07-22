pragma solidity ^0.8.19;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
// Do not use IERC20 because it does not expose the decimals() function.
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";

import {IBaseRestakingController} from "../interfaces/IBaseRestakingController.sol";
import {ICustomProxyAdmin} from "../interfaces/ICustomProxyAdmin.sol";
import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {IValidatorRegistry} from "../interfaces/IValidatorRegistry.sol";

import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";
import {IVault} from "../interfaces/IVault.sol";

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
        require(owner != address(0), "Bootstrap: owner should not be empty");
        require(spawnTime_ > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(offsetDuration_ > 0, "Bootstrap: offset duration should be greater than 0");
        require(spawnTime_ > offsetDuration_, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = spawnTime_ - offsetDuration_;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        require(customProxyAdmin_ != address(0), "Bootstrap: custom proxy admin should not be empty");

        exocoreSpawnTime = spawnTime_;
        offsetDuration = offsetDuration_;

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
        return block.timestamp >= exocoreSpawnTime - offsetDuration;
    }

    /// @dev Modifier to restrict operations based on the contract's defined timeline, that is,
    /// during the offset duration before the Exocore spawn time.
    modifier beforeLocked() {
        require(!isLocked(), "Bootstrap: operation not allowed after lock time");
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
    /// @param _spawnTime The new spawn time in seconds.
    function setSpawnTime(uint256 _spawnTime) external onlyOwner beforeLocked {
        require(_spawnTime > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(_spawnTime > offsetDuration, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = _spawnTime - offsetDuration;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        // technically the spawn time can be moved backwards in time as well.
        exocoreSpawnTime = _spawnTime;
        emit SpawnTimeUpdated(_spawnTime);
    }

    /// @notice Allows the contract owner to modify the offset duration that determines
    /// the lock period before the Exocore spawn time.
    /// @dev This function can only be called by the contract owner and must be called
    /// before the currently set lock time has started.
    /// @param _offsetDuration The new offset duration in seconds.
    function setOffsetDuration(uint256 _offsetDuration) external onlyOwner beforeLocked {
        require(exocoreSpawnTime > _offsetDuration, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = exocoreSpawnTime - _offsetDuration;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        offsetDuration = _offsetDuration;
        emit OffsetDurationUpdated(_offsetDuration);
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
        for (uint256 i; i < tokens.length; i++) {
            address token = tokens[i];
            require(token != address(0), "Bootstrap: zero token address");
            require(!isWhitelistedToken[token], "Bootstrap: token should be not whitelisted before");

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
        require(bytes(ethToExocoreAddress[msg.sender]).length == 0, "Ethereum address already linked to a validator");
        // check if validator with the same exocore address already exists
        require(
            bytes(validators[validatorAddress].name).length == 0,
            "Validator with this Exocore address is already registered"
        );
        // check that the consensus key is unique.
        require(!consensusPublicKeyInUse(consensusPublicKey), "Consensus public key already in use");
        // and that the name (meta info) is unique.
        require(!nameInUse(name), "Name already in use");
        // check that the commission is valid.
        require(isCommissionValid(commission), "invalid commission");
        ethToExocoreAddress[msg.sender] = validatorAddress;
        validators[validatorAddress] =
            IValidatorRegistry.Validator({name: name, commission: commission, consensusPublicKey: consensusPublicKey});
        registeredValidators.push(msg.sender);
        emit ValidatorRegistered(msg.sender, validatorAddress, name, commission, consensusPublicKey);
    }

    /// @notice Checks if the given consensus public key is already in use by any registered validator.
    /// @dev Iterates over all validators to determine if the key is in use.
    /// @param newKey The input key to check.
    /// @return bool Returns `true` if the key is already in use, `false` otherwise.
    function consensusPublicKeyInUse(bytes32 newKey) public view returns (bool) {
        require(newKey != bytes32(0), "Consensus public key cannot be zero");
        uint256 arrayLength = registeredValidators.length;
        for (uint256 i = 0; i < arrayLength; i++) {
            address ethAddress = registeredValidators[i];
            string memory exoAddress = ethToExocoreAddress[ethAddress];
            if (validators[exoAddress].consensusPublicKey == newKey) {
                return true;
            }
        }
        return false;
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

    /// @notice Checks if the given name is already in use by any registered validator.
    /// @dev Iterates over all validators to determine if the name is in use.
    /// @param newName The input name to check.
    /// @return bool Returns `true` if the name is already in use, `false` otherwise.
    function nameInUse(string memory newName) public view returns (bool) {
        uint256 arrayLength = registeredValidators.length;
        for (uint256 i = 0; i < arrayLength; i++) {
            address ethAddress = registeredValidators[i];
            string memory exoAddress = ethToExocoreAddress[ethAddress];
            if (keccak256(abi.encodePacked(validators[exoAddress].name)) == keccak256(abi.encodePacked(newName))) {
                return true;
            }
        }
        return false;
    }

    /// @inheritdoc IValidatorRegistry
    function replaceKey(bytes32 newKey) external beforeLocked whenNotPaused {
        require(bytes(ethToExocoreAddress[msg.sender]).length != 0, "no such validator exists");
        require(!consensusPublicKeyInUse(newKey), "Consensus public key already in use");
        validators[ethToExocoreAddress[msg.sender]].consensusPublicKey = newKey;
        emit ValidatorKeyReplaced(ethToExocoreAddress[msg.sender], newKey);
    }

    /// @inheritdoc IValidatorRegistry
    function updateRate(uint256 newRate) external beforeLocked whenNotPaused {
        string memory validatorAddress = ethToExocoreAddress[msg.sender];
        require(bytes(validatorAddress).length != 0, "no such validator exists");
        // across the lifetime of this contract before network bootstrap,
        // allow the editing of commission only once.
        require(!commissionEdited[validatorAddress], "Commission already edited once");
        Commission memory commission = validators[validatorAddress].commission;
        uint256 rate = commission.rate;
        uint256 maxRate = commission.maxRate;
        uint256 maxChangeRate = commission.maxChangeRate;
        // newRate <= maxRate <= 1e18
        require(newRate <= maxRate, "Rate exceeds max rate");
        // to prevent validators from blindsiding users by first registering at low rate and
        // subsequently increasing it, we should also check that the change is within the
        // allowed rate change.
        require(newRate <= rate + maxChangeRate, "Rate change exceeds max change rate");
        validators[validatorAddress].commission.rate = newRate;
        commissionEdited[validatorAddress] = true;
        emit ValidatorCommissionUpdated(newRate);
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
        require(deposited >= amount, "Bootstrap: insufficient deposited balance");
        uint256 withdrawable = withdrawableAmounts[user][token];
        require(withdrawable >= amount, "Bootstrap: insufficient withdrawable balance");

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
        require(msg.value == 0, "Bootstrap: no ether required for delegation");
        // check that validator is registered
        require(bytes(validators[validator].name).length != 0, "Validator does not exist");
        // validator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 withdrawable = withdrawableAmounts[msg.sender][token];
        require(withdrawable >= amount, "Bootstrap: insufficient withdrawable balance");
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
        require(msg.value == 0, "Bootstrap: no ether required for undelegation");
        // check that validator is registered
        require(bytes(validators[validator].name).length != 0, "Validator does not exist");
        // validator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 delegated = delegations[user][validator][token];
        require(delegated >= amount, "Bootstrap: insufficient delegated balance");
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
        require(block.timestamp >= exocoreSpawnTime, "Bootstrap: not yet in the bootstrap time");
        require(!bootstrapped, "Bootstrap: already bootstrapped");
        require(clientChainGatewayLogic != address(0), "Bootstrap: client chain gateway logic not set");
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
        require(_clientChainGatewayLogic != address(0), "Bootstrap: client chain gateway logic address cannot be empty");
        require(_clientChainInitializationData.length >= 4, "Bootstrap: client chain initialization data is malformed");
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
        require(index < whitelistTokens.length, "Index out of bounds");
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
