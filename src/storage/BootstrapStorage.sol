pragma solidity ^0.8.19;

import {IVault} from "../interfaces/IVault.sol";
import {GatewayStorage} from "./GatewayStorage.sol";

// BootstrapStorage should inherit from GatewayStorage since it exists
// prior to ClientChainGateway. ClientChainGateway should inherit from
// BootstrapStorage to ensure overlap of positioning between the
// members of each contract.
contract BootstrapStorage is GatewayStorage {
    /**
     * @notice A timestamp representing the scheduled spawn time of the Exocore chain, which
     * influences the contract's operational restrictions.
     *
     * @dev This variable sets a specific point in time (in UNIX timestamp format) that triggers
     * a freeze period for the contract 24 hours before the Exocore chain is expected to launch.
     * Operations that could alter the state of the contract significantly are not allowed
     * during this freeze period to ensure stability and integrity leading up to the spawn time.
     */
    uint256 public exocoreSpawnTime;

    /**
     * @notice The amount of time before the Exocore spawn time during which operations are
     * restricted.
     *
     * @dev This variable defines a period in seconds before the scheduled spawn time of the
     * Exocore chain, during which certain contract operations are locked to prevent state
     * changes. The lock period is intended to ensure stability and integrity of the contract
     * state leading up to the critical event. This period can be customized at the time of
     * contract deployment according to operational needs and security considerations.
     */
    uint256 public offsetTime;

    uint256[40] private __gap;
}