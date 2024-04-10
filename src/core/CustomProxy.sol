// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

abstract contract IBootstrapMarker {
    // 0xc605af52, does not conflict with ITransparentUpgradeableProxy
    function markBootstrapped() external virtual;
    // 0x25c858ad
    function upgradeLogicB(address) external virtual;
    // function admin() 0xf851a440
    // function implementation() 0x5c60da1b
    // function changeAdmin(address) 0x8f283970
    // function upgradeTo(address) 0x3659cfe6
    // function upgradeToAndCall(address, bytes memory) 0x4f1ef286
}

contract CustomProxy is TransparentUpgradeableProxy {
    address public immutable bootstrapAddress;
    address public logicB;
    bool public bootstrapped;

    constructor(
        address _logicA,
        address _admin,
        bytes memory _data,
        address _logicB,
        address _bootstrapAddress
    ) TransparentUpgradeableProxy(_logicA, _admin, _data) {
        // this contract is not designed to be upgradeable so
        // it is okay to do this in the constructor.
        logicB = _logicB;
        bootstrapAddress = _bootstrapAddress;
    }

    function _fallback() internal virtual override {
        // when the attempt is to mark bootstrap, switch over to the secondary logic.
        bool cond = msg.sender == bootstrapAddress &&
            !bootstrapped &&
            msg.sig == IBootstrapMarker.markBootstrapped.selector;
        if (cond) {
            bytes memory ret;
            bytes4 selector = msg.sig;
            bytes memory data = abi.encodeWithSelector(
                this._dispatchUpgradeTo.selector, logicB
            );
            (bool success, ret) = address(this).call(data);
            bootstrapped = true;
            assembly {
                // ends execution.
                return(add(ret, 0x20), mload(ret))
            }
        } else {
            // upgradeLogicB should be called only when not bootstrapped.
            // otherwise, use just the default TransparentUpgradeableProxy behavior.
            cond = msg.sender == _getAdmin() &&
                !bootstrapped &&
                msg.sig == IBootstrapMarker.upgradeLogicB.selector
            if (cond) {
                _logicB = abi.decode(msg.data[4:], (address));
                return;
            }
        }
        super._fallback();
    }
}