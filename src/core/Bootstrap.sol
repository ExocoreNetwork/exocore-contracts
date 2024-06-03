pragma solidity ^0.8.19;

// Do not use IERC20 because it does not expose the decimals() function.
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ITransparentUpgradeableProxy} from
    "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";

import {ILSTRestakingController} from "../interfaces/ILSTRestakingController.sol";
import {ICustomProxyAdmin} from "../interfaces/ICustomProxyAdmin.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {IVault} from "../interfaces/IVault.sol";

import {BootstrapLzReceiver} from "./BootstrapLzReceiver.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

// ClientChainGateway differences:
// replace IClientChainGateway with ITokenWhitelister (excludes only quote function).
// add a new interface for operator registration.
// replace ClientGatewayLzReceiver with BootstrapLzReceiver, which handles only incoming calls
// and not responses.
contract Bootstrap is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ILSTRestakingController,
    IOperatorRegistry,
    BootstrapLzReceiver
{
    constructor(address endpoint_, uint32 exocoreChainId_, address vaultBeacon_, address beaconProxyBytecode_)
        OAppCoreUpgradeable(endpoint_)
        BootstrapStorage(exocoreChainId_, vaultBeacon_, beaconProxyBytecode_)
    {
        _disableInitializers();
    }

    function initialize(
        address owner,
        uint256 spawnTime_,
        uint256 offsetDuration_,
        address payable exocoreValidatorSetAddress_,
        address[] calldata whitelistTokens_,
        address customProxyAdmin_
    ) external initializer {
        require(owner != address(0), "Bootstrap: owner should not be empty");
        require(spawnTime_ > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(offsetDuration_ > 0, "Bootstrap: offset duration should be greater than 0");
        require(spawnTime_ > offsetDuration_, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = spawnTime_ - offsetDuration_;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        require(
            exocoreValidatorSetAddress_ != address(0), "Bootstrap: exocore validator set address should not be empty"
        );
        require(customProxyAdmin_ != address(0), "Bootstrap: custom proxy admin should not be empty");

        exocoreSpawnTime = spawnTime_;
        offsetDuration = offsetDuration_;
        exocoreValidatorSetAddress = exocoreValidatorSetAddress_;

        for (uint256 i = 0; i < whitelistTokens_.length; i++) {
            address underlyingToken = whitelistTokens_[i];
            whitelistTokens.push(underlyingToken);
            isWhitelistedToken[underlyingToken] = true;
            emit WhitelistTokenAdded(underlyingToken);

            _deployVault(underlyingToken);
        }

        _whiteListFunctionSelectors[Action.MARK_BOOTSTRAP] = this.markBootstrapped.selector;

        customProxyAdmin = customProxyAdmin_;
        bootstrapped = false;

        // msg.sender is not the proxy admin but the transparent proxy itself, and hence,
        // cannot be used here. we must require a separate owner. since the Exocore validator
        // set can not sign without the chain, the owner is likely to be an EOA or a
        // contract controlled by one.
        __Ownable_init_unchained(owner);
        __Pausable_init_unchained();
    }

    /**
     * @notice Checks if the contract is locked, meaning it has passed the offset duration
     * before the Exocore spawn time.
     * @dev Returns true if the contract is locked, false otherwise.
     * @return bool Returns `true` if the contract is locked, `false` otherwise.
     */
    function isLocked() public view returns (bool) {
        return block.timestamp >= exocoreSpawnTime - offsetDuration;
    }

    /**
     * @dev Modifier to restrict operations based on the contract's defined timeline.
     * It checks if the current block timestamp is less than 24 hours before the
     * Exocore spawn time, effectively locking operations as the spawn time approaches
     * and afterwards. This is used to enforce a freeze period before the Exocore
     * chain's launch, ensuring no changes can be made during this critical time.
     *
     * The modifier is applied to functions that should be restricted by this timeline,
     * including registration, delegation, and token management operations. Attempting
     * to perform these operations during the lock period will result in a transaction
     * revert with an informative error message.
     */
    modifier beforeLocked() {
        require(!isLocked(), "Bootstrap: operation not allowed after lock time");
        _;
    }

    // pausing and unpausing can happen at all times, including after locked time.
    function pause() external onlyOwner {
        _pause();
    }

    // pausing and unpausing can happen at all times, including after locked time.
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Allows the contract owner to modify the spawn time of the Exocore
     * chain. This function can only be called by the contract owner and must
     * be called before the currently set lock time has started.
     *
     * @param _spawnTime The new spawn time in seconds.
     */
    function setSpawnTime(uint256 _spawnTime) external onlyOwner beforeLocked {
        require(_spawnTime > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(_spawnTime > offsetDuration, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = _spawnTime - offsetDuration;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        // technically the spawn time can be moved backwards in time as well.
        exocoreSpawnTime = _spawnTime;
        emit SpawnTimeUpdated(_spawnTime);
    }

    /**
     * @dev Allows the contract owner to modify the offset duration that determines
     * the lock period before the Exocore spawn time. This function can only be
     * called by the contract owner and must be called before the currently set
     * lock time has started.
     *
     * @param _offsetDuration The new offset duration in seconds.
     */
    function setOffsetDuration(uint256 _offsetDuration) external onlyOwner beforeLocked {
        require(exocoreSpawnTime > _offsetDuration, "Bootstrap: spawn time should be greater than offset duration");
        uint256 lockTime = exocoreSpawnTime - _offsetDuration;
        require(lockTime > block.timestamp, "Bootstrap: lock time should be in the future");
        offsetDuration = _offsetDuration;
        emit OffsetDurationUpdated(_offsetDuration);
    }

    // implementation of ITokenWhitelister
    function addWhitelistToken(address _token) public override beforeLocked onlyOwner whenNotPaused {
        super.addWhitelistToken(_token);
    }

    // implementation of ITokenWhitelister
    function removeWhitelistToken(address _token)
        public
        override
        beforeLocked
        onlyOwner
        whenNotPaused
        isTokenWhitelisted(_token)
    {
        super.removeWhitelistToken(_token);
    }

    // implementation of IOperatorRegistry
    function registerOperator(
        string calldata operatorExocoreAddress,
        string calldata name,
        Commission memory commission,
        bytes32 consensusPublicKey
    ) external beforeLocked whenNotPaused {
        // ensure the address format is valid.
        require(isValidExocoreAddress(operatorExocoreAddress), "Bootstrap: invalid bech32 address");
        // ensure that there is only one operator per ethereum address
        require(bytes(ethToExocoreAddress[msg.sender]).length == 0, "Ethereum address already linked to an operator");
        // check if operator with the same exocore address already exists
        require(
            bytes(operators[operatorExocoreAddress].name).length == 0,
            "Operator with this Exocore address is already registered"
        );
        // check that the consensus key is unique.
        require(!consensusPublicKeyInUse(consensusPublicKey), "Consensus public key already in use");
        // and that the name (meta info) is unique.
        require(!nameInUse(name), "Name already in use");
        // check that the commission is valid.
        require(isCommissionValid(commission), "invalid commission");
        ethToExocoreAddress[msg.sender] = operatorExocoreAddress;
        operators[operatorExocoreAddress] =
            IOperatorRegistry.Operator({name: name, commission: commission, consensusPublicKey: consensusPublicKey});
        registeredOperators.push(msg.sender);
        emit OperatorRegistered(msg.sender, operatorExocoreAddress, name, commission, consensusPublicKey);
    }

    /**
     * @dev Checks if a given consensus public key is already in use by any registered operator.
     *
     * This function iterates over all registered operators stored in the contract's state
     * to determine if the provided consensus public key matches any existing operator's
     * public key. It is designed to ensure the uniqueness of consensus public keys among
     * operators, as each operator must have a distinct consensus public key to maintain
     * integrity and avoid potential conflicts or security issues.
     *
     * @param newKey The consensus public key to check for uniqueness. This key is expected
     * to be provided as a byte32 array (`bytes32`), which is the typical format for
     * storing and handling public keys in Ethereum smart contracts.
     *
     * @return bool Returns `true` if the consensus public key is already in use by an
     * existing operator, indicating that the key is not unique. Returns `false` if the
     * public key is not found among the registered operators, indicating that the key
     * is unique and can be safely used for a new or updating operator.
     */
    function consensusPublicKeyInUse(bytes32 newKey) public view returns (bool) {
        require(newKey != bytes32(0), "Consensus public key cannot be zero");
        for (uint256 i = 0; i < registeredOperators.length; i++) {
            address ethAddress = registeredOperators[i];
            string memory exoAddress = ethToExocoreAddress[ethAddress];
            if (operators[exoAddress].consensusPublicKey == newKey) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Checks if the given commission settings are valid.
     * @dev Validates that the commission rate, max rate, and max change rate are within
     * acceptable bounds. Each parameter must be less than or equal to 1e18. The commission rate
     * must not exceed the max rate, and the max change rate must not exceed the max rate.
     * @param commission The commission structure containing the rate, max rate, and max change
     * rate to be validated.
     * @return bool Returns `true` if all conditions for a valid commission are met,
     * `false` otherwise.
     */
    function isCommissionValid(Commission memory commission) public pure returns (bool) {
        return commission.rate <= 1e18 && commission.maxRate <= 1e18 && commission.maxChangeRate <= 1e18
            && commission.rate <= commission.maxRate && commission.maxChangeRate <= commission.maxRate;
    }

    /**
     * @dev Checks if a given name is already in use by any registered operator.
     *
     * This function iterates over all registered operators stored in the contract's state
     * to determine if the provided name matches any existing operator's name. It is
     * designed to ensure the uniqueness of name (identity) among operators, as each
     * operator must have a distinct name to maintain integrity and avoid potential
     * conflicts or security issues.
     *
     * @param newName The name to check for uniqueness, as a string.
     *
     * @return bool Returns `true` if the name is already in use by an existing operator,
     * indicating that the name is not unique. Returns `false` if the name is not found
     * among the registered operators, indicating that the name is unique and can be
     * safely used for a new operator.
     */
    function nameInUse(string memory newName) public view returns (bool) {
        for (uint256 i = 0; i < registeredOperators.length; i++) {
            address ethAddress = registeredOperators[i];
            string memory exoAddress = ethToExocoreAddress[ethAddress];
            if (keccak256(abi.encodePacked(operators[exoAddress].name)) == keccak256(abi.encodePacked(newName))) {
                return true;
            }
        }
        return false;
    }

    // implementation of IOperatorRegistry
    function replaceKey(bytes32 newKey) external beforeLocked whenNotPaused {
        require(bytes(ethToExocoreAddress[msg.sender]).length != 0, "no such operator exists");
        require(!consensusPublicKeyInUse(newKey), "Consensus public key already in use");
        operators[ethToExocoreAddress[msg.sender]].consensusPublicKey = newKey;
        emit OperatorKeyReplaced(ethToExocoreAddress[msg.sender], newKey);
    }

    // implementation of IOperatorRegistry
    function updateRate(uint256 newRate) external beforeLocked whenNotPaused {
        string memory operatorAddress = ethToExocoreAddress[msg.sender];
        require(bytes(operatorAddress).length != 0, "no such operator exists");
        // across the lifetime of this contract before network bootstrap,
        // allow the editing of commission only once.
        require(!commissionEdited[operatorAddress], "Commission already edited once");
        Commission memory commission = operators[operatorAddress].commission;
        uint256 rate = commission.rate;
        uint256 maxRate = commission.maxRate;
        uint256 maxChangeRate = commission.maxChangeRate;
        // newRate <= maxRate <= 1e18
        require(newRate <= maxRate, "Rate exceeds max rate");
        // to prevent operators from blindsiding users by first registering at low rate and
        // subsequently increasing it, we should also check that the change is within the
        // allowed rate change.
        require(newRate <= rate + maxChangeRate, "Rate change exceeds max change rate");
        operators[operatorAddress].commission.rate = newRate;
        commissionEdited[operatorAddress] = true;
        emit OperatorCommissionUpdated(newRate);
    }

    // implementation of IController
    function deposit(address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        IVault vault = _getVault(token);
        vault.deposit(msg.sender, amount);

        if (!isDepositor[msg.sender]) {
            isDepositor[msg.sender] = true;
            depositors.push(msg.sender);
        }

        // staker_asset.go duplicate here. the duplication is required (and not simply inferred
        // from vault) because the vault is not altered by the gateway in response to
        // delegations or undelegations. hence, this is not something we can do either.
        totalDepositAmounts[msg.sender][token] += amount;
        withdrawableAmounts[msg.sender][token] += amount;
        depositsByToken[token] += amount;

        // afterReceiveDepositResponse stores the TotalDepositAmount in the principle.
        vault.updatePrincipleBalance(msg.sender, totalDepositAmounts[msg.sender][token]);

        emit DepositResult(true, token, msg.sender, amount);
    }

    // implementation of IController
    // This will allow release of undelegated (free) funds to the user for claiming separately.
    function withdrawPrincipleFromExocore(address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        IVault vault = _getVault(token);

        uint256 deposited = totalDepositAmounts[msg.sender][token];
        require(deposited >= amount, "Bootstrap: insufficient deposited balance");
        uint256 withdrawable = withdrawableAmounts[msg.sender][token];
        require(withdrawable >= amount, "Bootstrap: insufficient withdrawable balance");

        // when the withdraw precompile is called, it does these things.
        totalDepositAmounts[msg.sender][token] -= amount;
        withdrawableAmounts[msg.sender][token] -= amount;
        depositsByToken[token] -= amount;

        // afterReceiveWithdrawPrincipleResponse
        vault.updatePrincipleBalance(msg.sender, totalDepositAmounts[msg.sender][token]);
        vault.updateWithdrawableBalance(msg.sender, amount, 0);

        emit WithdrawPrincipleResult(true, token, msg.sender, amount);
    }

    // implementation of IController
    // there are no rewards before the network bootstrap, so this function is not supported.
    function withdrawRewardFromExocore(address, uint256) external payable override beforeLocked whenNotPaused {
        revert NotYetSupported();
    }

    // implementation of IController
    function claim(address token, uint256 amount, address recipient)
        external
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
    {
        IVault vault = _getVault(token);
        vault.withdraw(msg.sender, recipient, amount);
    }

    // implementation of IController
    function delegateTo(string calldata operator, address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
    {
        // check that operator is registered
        require(bytes(operators[operator].name).length != 0, "Operator does not exist");
        // operator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 withdrawable = withdrawableAmounts[msg.sender][token];
        require(withdrawable >= amount, "Bootstrap: insufficient withdrawable balance");
        delegations[msg.sender][operator][token] += amount;
        delegationsByOperator[operator][token] += amount;
        withdrawableAmounts[msg.sender][token] -= amount;

        emit DelegateResult(true, msg.sender, operator, token, amount);
    }

    // implementation of IController
    function undelegateFrom(string calldata operator, address token, uint256 amount)
        external
        payable
        override
        beforeLocked
        whenNotPaused
        isTokenWhitelisted(token)
        isValidAmount(amount)
        isValidBech32Address(operator)
    {
        // check that operator is registered
        require(bytes(operators[operator].name).length != 0, "Operator does not exist");
        // operator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 delegated = delegations[msg.sender][operator][token];
        require(delegated >= amount, "Bootstrap: insufficient delegated balance");
        // the undelegation is released immediately since it is not at stake yet.
        delegations[msg.sender][operator][token] -= amount;
        delegationsByOperator[operator][token] -= amount;
        withdrawableAmounts[msg.sender][token] += amount;

        emit UndelegateResult(true, msg.sender, operator, token, amount);
    }

    /**
     * @dev Marks the contract as bootstrapped when called from a valid source such as
     * LayerZero or the validator set via TSS.
     * @notice This function is triggered internally and is part of the bootstrapping process
     * that switches the contract's state to allow further interactions specific to the
     * bootstrapped mode.
     * It should only be called through `address(this).call(selector, data)` to ensure it
     * executes under specific security conditions.
     * This function includes modifiers to ensure it's called only internally and while the
     * contract is not paused.
     */
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

    /**
     * @dev Sets a new client chain gateway logic and its initialization data.
     * @notice Allows the contract owner to update the address and initialization data for the
     * client chain gateway logic. This is critical for preparing the contract setup before it's
     * bootstrapped. The change can only occur prior to bootstrapping.
     * @param _clientChainGatewayLogic The address of the new client chain gateway logic
     * contract.
     * @param _clientChainInitializationData The initialization data to be used when setting up
     * the new logic contract.
     */
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

    /**
     * @dev Gets the count of registered operators.
     * @return The number of registered operators.
     * @notice This function returns the total number of registered operators in the contract.
     */
    function getOperatorsCount() external view returns (uint256) {
        return registeredOperators.length;
    }

    /**
     * @dev Gets the count of depositors.
     * @return The number of depositors.
     * @notice This function returns the total number of depositors in the contract.
     */
    function getDepositorsCount() external view returns (uint256) {
        return depositors.length;
    }

    /**
     * @dev Gets the count of whitelisted tokens.
     * @return The number of whitelisted tokens.
     * @notice This function returns the total number of whitelisted tokens in the contract.
     */
    function getWhitelistedTokensCount() external view returns (uint256) {
        return whitelistTokens.length;
    }

    /**
     * @notice Retrieves information for a supported token by its index in the storage array.
     * @dev Returns comprehensive details about a token, including its ERC20 attributes and deposit amount.
     * @param index The index of the token in the `supportedTokens` array.
     * @return A `TokenInfo` struct containing the token's name, symbol, address, decimals, total supply, and deposit
     * amount.
     */
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
