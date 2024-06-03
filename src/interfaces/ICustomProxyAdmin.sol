pragma solidity ^0.8.19;

import {ITransparentUpgradeableProxy} from
    "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

interface ICustomProxyAdmin {
    function changeImplementation(ITransparentUpgradeableProxy proxy, address implementation, bytes memory data)
        external
        payable;
}
