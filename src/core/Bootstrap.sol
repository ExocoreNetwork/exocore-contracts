pragma solidity ^0.8.19;

import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin-upgradeable/contracts/utils/PausableUpgradeable.sol";

contract Bootstrap is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    BootstrapStorage
{
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner,
        uint256 _spawnTime,
        uint256 _offsetTime
    ) external initializer {
        require(owner != address(0), "Bootstrap: owner should not be empty");
        require(_spawnTime > block.timestamp, "Bootstrap: spawn time should be in the future");
        require(_offsetTime > 0, "Bootstrap: offset time should be greater than 0");

        exocoreSpawnTime = _spawnTime;
        offsetTime = _offsetTime;

        // msg.sender is not the proxy admin but the transparent proxy itself, and hence,
        // cannot be used here. we must require a separate owner. since the Exocore validator
        // set also does not exist, the owner is likely to be an EOA or a contract controlled
        // by one.
        __Ownable_init_unchained(owner);
        __Pausable_init_unchained();
    }

    function pause() onlyOwner external {
        _pause();
    }

    function unpause() onlyOwner external {
        _unpause();
    }
}