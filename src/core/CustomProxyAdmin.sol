pragma solidity ^0.8.19;

import {Errors} from "../libraries/Errors.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

// This contract is not upgradeable intentionally, since doing so would produce a lot of risk.
contract CustomProxyAdmin is Initializable, ProxyAdmin {

    // bootstrapper is the address of the Bootstrap storage (not the implementation).
    // in other words, it is that of the TransparentUpgradeableProxy.
    address public bootstrapper;

    constructor() ProxyAdmin() {}

    function initialize(address newBootstrapper) external initializer onlyOwner {
        if (newBootstrapper == address(0)) {
            revert Errors.ZeroAddress();
        }
        bootstrapper = newBootstrapper;
    }

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
