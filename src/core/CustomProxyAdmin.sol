pragma solidity ^0.8.19;

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ITransparentUpgradeableProxy} from
    "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";

// This contract is not upgradeable intentionally, since doing so would produce a lot of risk.
contract CustomProxyAdmin is Initializable, ProxyAdmin {
    // bootstrapper is the address of the Bootstrap storage (not the implementation).
    // in other words, it is that of the TransparentUpgradeableProxy.
    address public bootstrapper;

    constructor() ProxyAdmin() {}

    function initialize(address newBootstrapper) external initializer onlyOwner {
        bootstrapper = newBootstrapper;
    }

    function changeImplementation(address proxy, address implementation, bytes memory data) public virtual {
        require(msg.sender == bootstrapper, "CustomProxyAdmin: sender must be bootstrapper");
        require(msg.sender == proxy, "CustomProxyAdmin: sender must be the proxy itself");
        ITransparentUpgradeableProxy(proxy).upgradeToAndCall(implementation, data);
        bootstrapper = address(0);
    }
}
