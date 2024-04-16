pragma solidity ^0.8.19;

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {OAppCoreUpgradeable} from "../lzApp/OAppCoreUpgradeable.sol";

import {IController} from "../interfaces/IController.sol";
import {ICustomProxyAdmin} from "../interfaces/ICustomProxyAdmin.sol";
import {IOperatorRegistry} from "../interfaces/IOperatorRegistry.sol";
import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";
import {IVault} from "../interfaces/IVault.sol";

import {ClientChainLzReceiver} from "./ClientChainLzReceiver.sol";
import {TSSReceiver} from "./TSSReceiver.sol";

// ClientChainGateway differences:
// replace IClientChainGateway with ITokenWhitelister (excludes only quote function).
// and add a new interface for operator registration.
// note that bootstrap storage by itself is not used, but rather we are using
// ClientChainGatewayStorage indirectly through the layer zero receiver and the TSS receiver.
contract Bootstrap is
    Initializable,
    PausableUpgradeable,
    OwnableUpgradeable,
    ITokenWhitelister,
    IController,
    IOperatorRegistry,
    ClientChainLzReceiver,
    TSSReceiver
{
    constructor(address _endpoint) OAppCoreUpgradeable(_endpoint) {
        _disableInitializers();
    }

    function initialize(
        address owner,
        uint256 _spawnTime,
        uint256 _offsetTime,
        uint32 _exocoreChainId,
        address payable _exocoreValidatorSetAddress,
        address[] calldata _whitelistTokens,
        address _customProxyAdmin
    ) external initializer {
        require(owner != address(0), "Bootstrap: owner should not be empty");
        require(_spawnTime > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(_offsetTime > 0, "Bootstrap: offset time should be greater than 0");
        require(_exocoreChainId != 0, "Bootstrap: exocore chain id should not be empty");
        require(_exocoreValidatorSetAddress != address(0),
            "Bootstrap: exocore validator set address should not be empty");

        exocoreSpawnTime = _spawnTime;
        offsetTime = _offsetTime;
        exocoreChainId = _exocoreChainId;
        exocoreValidatorSetAddress = _exocoreValidatorSetAddress;
        for (uint256 i = 0; i < _whitelistTokens.length; i++) {
            whitelistTokens[_whitelistTokens[i]] = true;
            whitelistTokensArray.push(_whitelistTokens[i]);
        }

        whiteListFunctionSelectors[Action.MARK_BOOTSTRAP] =
            this.markBootstrapped.selector;

        customProxyAdmin = _customProxyAdmin;
        bootstrapped = false;

        // msg.sender is not the proxy admin but the transparent proxy itself, and hence,
        // cannot be used here. we must require a separate owner. since the Exocore validator
        // set can not sign without the chain, the owner is likely to be an EOA or a
        // contract controlled by one.
        __Ownable_init_unchained(owner);
        __Pausable_init_unchained();
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
    modifier beforeLocked {
        require(
            block.timestamp < exocoreSpawnTime - offsetTime,
            "Bootstrap: operation not allowed after lock time"
        );
        _;
    }

    // pausing and unpausing can happen at all times, including after locked time.
    function pause() onlyOwner external {
        _pause();
    }

    // pausing and unpausing can happen at all times, including after locked time.
    function unpause() onlyOwner external {
        _unpause();
    }

    /**
     * @dev Allows the contract owner to modify the spawn time of the Exocore
     * chain. This function can only be called by the contract owner and must
     * be called before the currently set lock time has started.
     *
     * @param spawnTime The new spawn time in seconds.
     */
    function setSpawnTime(uint256 spawnTime) external onlyOwner beforeLocked {
        exocoreSpawnTime = spawnTime;
        emit SpawnTimeUpdated(spawnTime);
    }

    /**
     * @dev Allows the contract owner to modify the offset time that determines
     * the lock period before the Exocore spawn time. This function can only be
     * called by the contract owner and must be called before the currently set
     * lock time has started.
     *
     * @param _offsetTime The new offset time in seconds.
     */
    function setOffsetTime(uint256 _offsetTime) external onlyOwner beforeLocked {
        offsetTime = _offsetTime;
        emit OffsetTimeUpdated(_offsetTime);
    }

    // implementation of ITokenWhitelister
    function addWhitelistToken(
        address _token
    ) external beforeLocked onlyOwner whenNotPaused {
        // modifiers: onlyOwner and whenNotPaused copied from client chain gateway.
        // i added beforeLocked to ensure that new tokens may not be added after
        // the offset time before the spawn time begins.
        // anyway it would be pointless to add such tokens since other operations
        // cannot be performed.
        require(
            !whitelistTokens[_token],
            "Bootstrap: token should be not whitelisted before"
        );
        whitelistTokens[_token] = true;
        whitelistTokensArray.push(_token);

        emit WhitelistTokenAdded(_token);
    }

    // implementation of ITokenWhitelister
    function removeWhitelistToken(
        address _token
    ) external beforeLocked onlyOwner whenNotPaused {
        require(
            whitelistTokens[_token],
            "Bootstrap: token should be already whitelisted"
        );
        whitelistTokens[_token] = false;
        for(uint i = 0; i < whitelistTokensArray.length; i++) {
            if (whitelistTokensArray[i] == _token) {
                whitelistTokensArray[i] = whitelistTokensArray[whitelistTokensArray.length - 1];
                whitelistTokensArray.pop();
                break;
            }
        }

        emit WhitelistTokenRemoved(_token);
    }

    // implementation of ITokenWhitelister
    function addTokenVaults(
        address[] calldata vaults
    ) external beforeLocked onlyOwner whenNotPaused {
        for (uint256 i = 0; i < vaults.length; i++) {
            address underlyingToken = IVault(vaults[i]).getUnderlyingToken();
            if (!whitelistTokens[underlyingToken]) {
                revert UnauthorizedToken();
            }
            tokenVaults[underlyingToken] = IVault(vaults[i]);

            emit VaultAdded(vaults[i]);
        }
    }

    // implementation of IOperatorRegistry
    function registerOperator(
        string calldata operatorExocoreAddress,
        string calldata name,
        Commission memory commission,
        bytes32 consensusPublicKey
    ) external beforeLocked whenNotPaused {
        // ensure the address format is valid.
        require(
            bytes(operatorExocoreAddress).length == 42,
            "Bootstrap: invalid bech32 address"
        );
        // ensure that there is only one operator per ethereum address
        require(
            bytes(ethToExocoreAddress[msg.sender]).length == 0,
            "Ethereum address already linked to an operator"
        );
        // check if operator with the same exocore address already exists
        require(
            bytes(operators[operatorExocoreAddress].name).length == 0,
            "Operator with this Exocore address is already registered"
        );
        // check that the consensus key is unique.
        require(
            !consensusPublicKeyInUse(consensusPublicKey),
            "Consensus public key already in use"
        );
        // and that the name (meta info) is unique.
        require(
            !nameInUse(name),
            "Name already in use"
        );
        // check that the commission is valid.
        require(
            isCommissionValid(commission),
            "invalid commission"
        );
        ethToExocoreAddress[msg.sender] = operatorExocoreAddress;
        operators[operatorExocoreAddress] = IOperatorRegistry.Operator({
            name: name,
            commission: commission,
            consensusPublicKey: consensusPublicKey
        });
        registeredOperators.push(msg.sender);
        emit OperatorRegistered(
            msg.sender,
            operatorExocoreAddress,
            name,
            commission,
            consensusPublicKey
        );
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
        return
            commission.rate <= 1e18 &&
            commission.maxRate <= 1e18 &&
            commission.maxChangeRate <= 1e18 &&
            commission.rate <= commission.maxRate &&
            commission.maxChangeRate <= commission.maxRate;
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
            if (keccak256(abi.encodePacked(operators[exoAddress].name)) ==
                keccak256(abi.encodePacked(newName))) {
                return true;
            }
        }
        return false;
    }

    // implementation of IOperatorRegistry
    function replaceKey(
        bytes32 newKey
    ) external beforeLocked whenNotPaused {
        require(
            bytes(ethToExocoreAddress[msg.sender]).length != 0,
            "no such operator exists"
        );
        require(
            !consensusPublicKeyInUse(newKey),
            "Consensus public key already in use"
        );
        operators[ethToExocoreAddress[msg.sender]].consensusPublicKey = newKey;
        emit OperatorKeyReplaced(ethToExocoreAddress[msg.sender], newKey);
    }

    // implementation of IOperatorRegistry
    function updateRate(
        uint256 newRate
    ) external beforeLocked whenNotPaused {
        string memory operatorAddress = ethToExocoreAddress[msg.sender];
        require(
            bytes(operatorAddress).length != 0,
            "no such operator exists"
        );
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
        require(
            newRate <= rate + maxChangeRate,
            "Rate change exceeds max change rate"
        );
        operators[operatorAddress].commission.rate = newRate;
        commissionEdited[operatorAddress] = true;
    }

    // implementation of IController
    function deposit(
        address token, uint256 amount
    ) override external payable beforeLocked whenNotPaused {
        require(whitelistTokens[token], "Bootstrap: token is not whitelisted");
        require(amount > 0, "Bootstrap: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }
        vault.deposit(msg.sender, amount);

        uint256 previous = totalDepositAmounts[msg.sender][token];
        if (previous == 0) {
            depositors.push(msg.sender);
        }

        // staker_asset.go duplicate here. the duplication is required (and not simply inferred
        // from vault) because the vault is not altered by the gateway in response to
        // delegations or undelegations. hence, this is not something we can do either.
        totalDepositAmounts[msg.sender][token] += amount;
        withdrawableAmounts[msg.sender][token] += amount;

        // afterReceiveDepositResponse stores the TotalDepositAmount in the principle.
        vault.updatePrincipleBalance(msg.sender, totalDepositAmounts[msg.sender][token]);
    }

    // implementation of IController
    // This will allow release of undelegated (free) funds to the user for claiming separately.
    function withdrawPrincipleFromExocore(
        address token, uint256 amount
    ) override external payable beforeLocked whenNotPaused {
        require(whitelistTokens[token], "Bootstrap: token is not whitelisted");
        require(amount > 0, "Bootstrap: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        uint256 deposited = totalDepositAmounts[msg.sender][token];
        require(
            deposited >= amount,
            "Bootstrap: insufficient deposited balance"
        );
        uint256 withdrawable = withdrawableAmounts[msg.sender][token];
        require(
            withdrawable >= amount,
            "Bootstrap: insufficient withdrawable balance"
        );

        totalDepositAmounts[msg.sender][token] -= amount;
        withdrawableAmounts[msg.sender][token] -= amount;

        // afterReceiveWithdrawPrincipleResponse
        vault.updatePrincipleBalance(msg.sender, totalDepositAmounts[msg.sender][token]);
        vault.updateWithdrawableBalance(msg.sender, amount, 0);
    }

    // implementation of IController
    // there are no rewards before the network bootstrap, so this function is not supported.
    function withdrawRewardFromExocore(
        address, uint256
    ) override external payable beforeLocked whenNotPaused {
        revert NotYetSupported();
    }

    // implementation of IController
    function claim(
        address token, uint256 amount, address recipient
    ) override external beforeLocked whenNotPaused {
        require(whitelistTokens[token], "Bootstrap: token is not whitelisted");
        require(amount > 0, "Bootstrap: amount should be greater than zero");

        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }

        vault.withdraw(msg.sender, recipient, amount);
    }

    // implementation of IController
    // this function is not required before the network bootstrap.
    function updateUsersBalances(
        UserBalanceUpdateInfo[] calldata
    ) view override external beforeLocked whenNotPaused {
        revert NotYetSupported();
    }

    // implementation of IController
    function delegateTo(
        string calldata operator, address token, uint256 amount
    ) override external payable beforeLocked whenNotPaused {
        // client chain checks
        require(whitelistTokens[token], "Bootstrap: token is not whitelisted");
        require(amount > 0, "Bootstrap: amount should be greater than zero");
        require(bytes(operator).length == 42, "Bootstrap: invalid bech32 address");
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }
        // check that operator is registered
        require(
            bytes(operators[operator].name).length != 0,
            "Operator does not exist"
        );
        // operator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 withdrawable = withdrawableAmounts[msg.sender][token];
        require(
            withdrawable >= amount,
            "Bootstrap: insufficient withdrawable balance"
        );
        delegations[msg.sender][operator][token] += amount;
        withdrawableAmounts[msg.sender][token] -= amount;
    }

    // implementation of IController
    function undelegateFrom(
        string calldata operator, address token, uint256 amount
    ) override external payable beforeLocked whenNotPaused {
        // client chain checks
        require(whitelistTokens[token], "Bootstrap: token is not whitelisted");
        require(amount > 0, "Bootstrap: amount should be greater than zero");
        require(bytes(operator).length == 42, "Bootstrap: invalid bech32 address");
        IVault vault = tokenVaults[token];
        if (address(vault) == address(0)) {
            revert VaultNotExist();
        }
        // check that operator is registered
        require(
            bytes(operators[operator].name).length != 0,
            "Operator does not exist"
        );
        // operator can't be frozen and amount can't be negative
        // asset validity has been checked.
        // now check amounts.
        uint256 delegated = delegations[msg.sender][operator][token];
        require(
            delegated >= amount,
            "Bootstrap: insufficient delegated balance"
        );
        // the undelegation is released immediately since it is not at stake yet.
        delegations[msg.sender][operator][token] -= amount;
        withdrawableAmounts[msg.sender][token] += amount;
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
        require(
            block.timestamp >= exocoreSpawnTime,
            "Bootstrap: not yet in the bootstrap time"
        );
        require(
            !bootstrapped,
            "Bootstrap: already bootstrapped"
        );
        require(
            clientChainGatewayLogic != address(0),
            "Bootstrap: client chain gateway logic not set"
        );
        ICustomProxyAdmin(customProxyAdmin).changeImplementation(
            // address(this) is storage address and not logic address. so it is a proxy.
            ITransparentUpgradeableProxy(address(this)),
            clientChainGatewayLogic, clientChainInitializationData
        );
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
    function setClientChainGatewayLogic(
        address _clientChainGatewayLogic,
        bytes calldata _clientChainInitializationData
    ) public onlyOwner {
        clientChainGatewayLogic = _clientChainGatewayLogic;
        clientChainInitializationData = _clientChainInitializationData;
    }

    function getOperatorsCount(
    ) external view returns (uint256) {
        return registeredOperators.length;
    }

    function getDepositorsCount(
    ) external view returns (uint256) {
        return depositors.length;
    }

    function getWhitelistedTokensCount(
    ) external view returns (uint256) {
        return whitelistTokensArray.length;
    }
}