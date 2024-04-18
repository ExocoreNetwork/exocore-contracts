// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CustomProxyAdmin} from "../../src/core/CustomProxyAdmin.sol";
import {ICustomProxyAdmin} from "../../src/interfaces/ICustomProxyAdmin.sol";

import "forge-std/console.sol";
import "forge-std/Test.sol";

import {Initializable} from "@openzeppelin-upgradeable/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract StorageOld {
    bool public implementationChanged;
}

contract StorageNew is StorageOld {
    bool public hi;
}

contract ImplementationChanger is Initializable, StorageOld {
    constructor() {
        _disableInitializers();
    }

    function initialize() external initializer {
        implementationChanged = false;
    }

    function changeImplementation(
        address customProxyAdmin,
        address newImplementation
    ) public {
        ICustomProxyAdmin(customProxyAdmin).changeImplementation(
            ITransparentUpgradeableProxy(address(this)),
            newImplementation, abi.encodeCall(
                NewImplementation.initialize, ()
            )
        );
    }
}

contract NewImplementation is Initializable, StorageNew {
    constructor() {
        _disableInitializers();
    }

    function initialize() external reinitializer(2) {
        implementationChanged = true;
        hi = true;
    }
}

contract CustomProxyAdminTest is Test {
    CustomProxyAdmin proxyAdmin;

    function setUp() public {
        proxyAdmin = new CustomProxyAdmin();
    }

    function test01_Initialize() public {
        address bootstrapper = address(0x123);
        proxyAdmin.initialize(bootstrapper);
        assertEq(proxyAdmin.bootstrapper(), bootstrapper);

        vm.expectRevert();
        proxyAdmin.initialize(address(0x1));
    }

    function test02_ChangeImplementation() public {
        // initialize the contract
        ImplementationChanger implementationChanger = ImplementationChanger(
            address(
                new TransparentUpgradeableProxy(
                    address(new ImplementationChanger()),
                    address(proxyAdmin),
                    abi.encodeCall(ImplementationChanger.initialize, ())
                )
            )
        );
        // validate that the implementation has not changed already
        assertFalse(implementationChanger.implementationChanged());
        // check that it does not have a `hi` function in there.
        NewImplementation newImplementation = NewImplementation(
            address(implementationChanger)
        );
        vm.expectRevert();  // EVM error
        assertFalse(newImplementation.hi());
        // now change the implementation
        proxyAdmin.initialize(address(implementationChanger));
        implementationChanger.changeImplementation(
            address(proxyAdmin),
            address(new NewImplementation())
        );
        // validate that it has changed
        assertTrue(implementationChanger.implementationChanged());
        assertTrue(newImplementation.hi());
    }

    function test02_ChangeImplementation_NotBootstrapper() public {
        // initialize the contract
        ImplementationChanger implementationChanger = ImplementationChanger(
            address(
                new TransparentUpgradeableProxy(
                    address(new ImplementationChanger()),
                    address(proxyAdmin),
                    abi.encodeCall(ImplementationChanger.initialize, ())
                )
            )
        );
        // validate that the implementation has not changed already
        assertFalse(implementationChanger.implementationChanged());
        // now change the implementation
        // for some reason, i could not get `vm.expectRevert` to work here.
        // if i had that line, it would not revert.
        // if i didn't have that line, it would not revert.
        try implementationChanger.changeImplementation(
                address(proxyAdmin),
                address(new NewImplementation())
        ) {
            // should never happen
            assertTrue(false);
        } catch {}
        assertFalse(implementationChanger.implementationChanged());
    }

    function test02_ChangeImplementation_NotProxy() public {
        // initialize the contract
        ImplementationChanger implementationChanger = ImplementationChanger(
            address(
                new TransparentUpgradeableProxy(
                    address(new ImplementationChanger()),
                    address(proxyAdmin),
                    abi.encodeCall(ImplementationChanger.initialize, ())
                )
            )
        );
        // validate that the implementation has not changed already
        assertFalse(implementationChanger.implementationChanged());
        // now change the implementation
        proxyAdmin.initialize(address(0x1));
        vm.startPrank(address(0x1));
        // same logic as above for using a try/catch.
        try proxyAdmin.changeImplementation(
            // the call is made to the ProxyAdmin from address(0x1)
            // when instead it should have been made from the TransparentUpgradeableProxy
            address(implementationChanger),
            address(new NewImplementation()),
            abi.encodeCall(NewImplementation.initialize, ())
        ) {
            // should never happen
            assertTrue(false);
        } catch {}
        assertFalse(implementationChanger.implementationChanged());
    }
}