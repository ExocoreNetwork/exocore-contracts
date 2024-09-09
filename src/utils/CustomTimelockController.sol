// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/governance/TimelockController.sol";

interface IPausable {

    function pause() external;
    function unpause() external;

}

contract CustomTimelockController is TimelockController {

    bytes32 public constant CIRCUIT_BREAKER_ROLE = keccak256("CIRCUIT_BREAKER_ROLE");

    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address[] memory circuitBreakers,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {
        _setRoleAdmin(CIRCUIT_BREAKER_ROLE, TIMELOCK_ADMIN_ROLE);

        // Grant CIRCUIT_BREAKER_ROLE to the specified circuit breakers
        for (uint256 i = 0; i < circuitBreakers.length; i++) {
            _setupRole(CIRCUIT_BREAKER_ROLE, circuitBreakers[i]);
        }
    }

    function pause(address target) external onlyRole(CIRCUIT_BREAKER_ROLE) {
        require(target != address(0), "CustomTimelockController: invalid target");
        IPausable(target).pause();
    }

}
