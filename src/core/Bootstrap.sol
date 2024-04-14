pragma solidity ^0.8.19;

import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

import {ITokenWhitelister} from "../interfaces/ITokenWhitelister.sol";
import {IVault} from "../interfaces/IVault.sol";

contract Bootstrap is
    BootstrapStorage,
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ITokenWhitelister
{
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner,
        uint256 _spawnTime,
        uint256 _offsetTime,
        address[] calldata _whitelistTokens
    ) external initializer {
        require(owner != address(0), "Bootstrap: owner should not be empty");
        require(_spawnTime > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(_offsetTime > 0, "Bootstrap: offset time should be greater than 0");

        exocoreSpawnTime = _spawnTime;
        offsetTime = _offsetTime;

        for (uint256 i = 0; i < _whitelistTokens.length; i++) {
            whitelistTokens[_whitelistTokens[i]] = true;
        }

        // msg.sender is not the proxy admin but the transparent proxy itself, and hence,
        // cannot be used here. we must require a separate owner. since the Exocore validator
        // set also does not exist, the owner is likely to be an EOA or a contract controlled
        // by one.
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
        require(block.timestamp < exocoreSpawnTime - offsetTime, "Bootstrap: operation not allowed after lock time");
        _;
    }

    // pausing and unpausing can happen at all times, including after locked time.
    function pause() onlyOwner external {
        _pause();
    }

    function unpause() onlyOwner external {
        _unpause();
    }

    function addWhitelistToken(address _token) external beforeLocked onlyOwner whenNotPaused {
        require(!whitelistTokens[_token], "ClientChainGateway: token should be not whitelisted before");
        whitelistTokens[_token] = true;

        emit WhitelistTokenAdded(_token);
    }

    function removeWhitelistToken(address _token) external beforeLocked onlyOwner whenNotPaused {
        require(whitelistTokens[_token], "ClientChainGateway: token should be already whitelisted");
        whitelistTokens[_token] = false;

        emit WhitelistTokenRemoved(_token);
    }

    function addTokenVaults(address[] calldata vaults) external beforeLocked onlyOwner whenNotPaused {
        for (uint256 i = 0; i < vaults.length; i++) {
            address underlyingToken = IVault(vaults[i]).getUnderlyingToken();
            if (!whitelistTokens[underlyingToken]) {
                revert UnauthorizedToken();
            }
            tokenVaults[underlyingToken] = IVault(vaults[i]);

            emit VaultAdded(vaults[i]);
        }
    }
}