pragma solidity ^0.8.19;

import { ITransparentUpgradeableProxy } from "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/ProxyAdmin.sol";

// This contract is not upgradeable intentionally, since doing so would produce a lot of risk.
contract CustomProxyAdmin is ProxyAdmin {
    // bootstrapper is the address of the Bootstrap storage (not the implementation).
    // in other words, it is that of the TransparentUpgradeableProxy.
    address bootstrapper;

    constructor() ProxyAdmin() {}

    function setBootstrapper(address newBootstrapper) public onlyOwner {
        bootstrapper = newBootstrapper;
    }

    function changeImplementation(
        ITransparentUpgradeableProxy proxy,
        address implementation,
        bytes memory data
    ) public virtual {
        require(msg.sender == bootstrapper, "CustomProxyAdmin: sender must be bootstrapper");
        require(
            msg.sender == address(proxy),
            "CustomProxyAdmin: sender must be the proxy itself"
        );
        proxy.upgradeToAndCall(implementation, data);
    }
}