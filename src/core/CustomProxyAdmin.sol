// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/// @title CustomProxyAdmin
/// @author ExocoreNetwork
/// @notice CustomProxyAdmin is a custom implementation of ProxyAdmin that allows a proxy contract to upgrade its own
/// implementation.
/// @dev This contract is not upgradeable intentionally, since doing so would produce a lot of risk.
contract CustomProxyAdmin is Initializable, ProxyAdmin {

    /// @notice The address of the proxy which will upgrade itself.
    address public bootstrapper;

    constructor() ProxyAdmin() {}

    /// @notice Initializes the CustomProxyAdmin contract.
    /// @param newBootstrapper The address of the proxy which will upgrade itself.
    function initialize(address newBootstrapper) external initializer onlyOwner {
        if (newBootstrapper == address(0)) {
            revert Errors.ZeroAddress();
        }
        bootstrapper = newBootstrapper;
    }

    /// @notice Changes the implementation of the proxy contract.
    /// @param proxy The address of the proxy contract.
    /// @param implementation The address of the new implementation contract.
    /// @param data The data to be passed to the new implementation contract.
    /// @dev This function can only be called by the proxy to upgrade itself, exactly once.
    function changeImplementation(address proxy, address implementation, bytes memory data) public virtual {
        if (msg.sender != bootstrapper) {
            revert Errors.CustomProxyAdminOnlyCalledFromBootstrapper();
        }
        if (msg.sender != proxy) {
            revert Errors.CustomProxyAdminOnlyCalledFromProxy();
        }

        // we follow check-effects-interactions pattern to write state before external call
        bootstrapper = address(0);
        ITransparentUpgradeableProxy(proxy).upgradeToAndCall(implementation, data);
    }

}
