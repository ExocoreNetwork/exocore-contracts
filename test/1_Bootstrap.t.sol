// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Test.sol";
import "../src/core/Bootstrapping.sol";
import "../test/MyToken.sol";

contract BootstrappingTest is Test {
    MyToken myToken;
    Bootstrapping bootstrappingContract;
    address[] addrs = new address[](6);
    uint256[] amounts = [
        35 * 10 ** 18,  // self
        25 * 10 ** 18,  // self
        10 * 10 ** 18,  // self
        17 * 10 ** 18,  // 8 + 9 + 0
        15 * 10 ** 18,  // 0 + 7 + 8
        8 * 10 ** 18    // 2 + 0 + 6
    ];
    address deployer = address(0xdeadbeef);
    uint256 spawnTime;
    uint256 offsetTime;

    function setUp() public {

        addrs[0] = address(0x1); // Simulated OPERATOR1 address
        addrs[1] = address(0x2); // Simulated OPERATOR2 address
        addrs[2] = address(0x3); // Simulated OPERATOR3 address
        addrs[3] = address(0x4); // Simulated STAKER1 address
        addrs[4] = address(0x5); // Simulated STAKER2 address
        addrs[5] = address(0x6); // Simulated STAKER3 address

        spawnTime = block.timestamp + 1 hours;
        offsetTime = 30 minutes;

        vm.startPrank(deployer);
        // first deploy the token
        myToken = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        // then create the params
        address[] memory tokenAddresses = new address[](1);
        tokenAddresses[0] = address(myToken);
        // finally, deploy the contract
        bootstrappingContract = new Bootstrapping(
            tokenAddresses, spawnTime, offsetTime, address(0x20)
        );
        vm.stopPrank();
    }

    function test01_IsTokenSupported() public {
        assertTrue(
            bootstrappingContract.isTokenSupported(address(myToken)),
            "MyToken"
        );
        assertTrue(
            !bootstrappingContract.isTokenSupported(address(0xa)),
            "Random"
        );
    }

    function test02_Deposit() public {
        // Distribute MyToken to addresses
        vm.startPrank(deployer);
        for (uint256 i = 0; i < 6; i++) {
            myToken.transfer(addrs[i], amounts[i]);
        }
        vm.stopPrank();
        // check balance
        for (uint256 i = 0; i < 6; i++) {
            uint256 balance = myToken.balanceOf(addrs[i]);
            assertTrue(balance >= amounts[i]);
        }

        // Make deposits
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            myToken.approve(address(bootstrappingContract), amounts[i]);
            bootstrappingContract.deposit(address(myToken), amounts[i]);
            vm.stopPrank();
        }

        // check values
        for (uint256 i = 0; i < 6; i++) {
            (uint256 amount, ) = bootstrappingContract.userDeposits(addrs[i], address(myToken));
            assertTrue(amount == amounts[i]);
        }
    }

    function test02_Deposit_WithoutApproval() public {
        // make a transfer
        vm.startPrank(deployer);
        myToken.transfer(addrs[0], amounts[0]);
        vm.stopPrank();
        assertTrue(myToken.balanceOf(addrs[0]) >= amounts[0]);

        // now try to deposit
        vm.startPrank(addrs[0]);
        vm.expectRevert("ERC20: insufficient allowance");
        bootstrappingContract.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_ZeroBalance() public {
        // Make deposits without having any balance
        vm.startPrank(addrs[0]);
        uint256 balance = myToken.balanceOf(addrs[0]);
        myToken.burn(balance);
        assertTrue(myToken.balanceOf(addrs[0]) == 0);
        myToken.approve(address(bootstrappingContract), amounts[0]);
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        bootstrappingContract.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_UnsupportedToken() public {
        address cloneDeployer = address(0xdebd);
        // Deploy a new token
        vm.startPrank(cloneDeployer);
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        address cloneAddress = address(myTokenClone);
        vm.stopPrank();

        // now transfer it to address[0]
        vm.startPrank(cloneDeployer);
        myTokenClone.transfer(addrs[0], amounts[0]);
        vm.stopPrank();

        // now try to deposit
        myToken.approve(address(bootstrappingContract), amounts[0]);
        vm.expectRevert("Token not supported");
        bootstrappingContract.deposit(cloneAddress, amounts[0]);
        vm.stopPrank();
    }

    function test03_RegisterOperator() public {
        assertTrue(bootstrappingContract.getOperatorsCount() == 0);
        // Register operators
        string[3] memory names = ["operator1", "operator2", "operator3"];
        bytes32[3] memory pubKeys = [
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782),
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9),
            bytes32(0xa29429a3ca352334fbe75df9485544bd517e3718df73725f33c6d06f3c1caade)
        ];
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // We can convert an operator's bech32 address to hex as follows.
        // exocored keys add --algo eth_secp256k1 MY_KEY --keyring-backend file
        // Then convert it to Eth-compatible version.
        // cast 2a \
        // $(exocored keys parse $(exocored keys show -a MY_KEY --keyring-backend file) \
        // --output json | jq .bytes)
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            bootstrappingContract.registerOperator(
                pubKeys[i], addrs[i], names[i], commission
            );
            assertTrue(bootstrappingContract.getOperatorsCount() == i + 1);
            vm.stopPrank();
        }
    }

    function test03_RegisterOperator_AlreadyRegistered() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register operator
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrappingContract.registerOperator(
            pubKey, addrs[0], name, commission
        );
        // change all params except address of operator
        pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        name = "operator1_re";
        vm.expectRevert("Operator already registered");
        bootstrappingContract.registerOperator(
            pubKey, addrs[0], name, commission
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_ConsensusKeyInUse() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register operator
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrappingContract.registerOperator(
            pubKey, addrs[0], name, commission
        );
        vm.stopPrank();

        // Register another operator with the same consensus key
        vm.startPrank(addrs[1]);
        name = "operator2";
        vm.expectRevert("Consensus public key already in use");
        bootstrappingContract.registerOperator(
            pubKey, addrs[1], name, commission
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_ExocoreZeroAddress() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register operator
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        vm.expectRevert("Exocore address cannot be zero");
        bootstrappingContract.registerOperator(
            pubKey, address(0), name, commission
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_NameInUse() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register operator
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrappingContract.registerOperator(
            pubKey, addrs[0], name, commission
        );
        vm.stopPrank();

        // Register another operator with the same name
        vm.startPrank(addrs[1]);
        name = "operator1";
        pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Name already in use");
        bootstrappingContract.registerOperator(
            pubKey, addrs[1], name, commission
        );
        vm.stopPrank();
    }

    function test04_DeregisterOperator() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // the tests run independently, so we start with 0 again.
        assertTrue(bootstrappingContract.getOperatorsCount() == 0);
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        bootstrappingContract.registerOperator(
            bytes32(0x440eeb74aa733f646fbe53e0e26c1659b4e2f081e9cbe0163521380eebb93771),
            addr, "operator4", commission
        );
        assertTrue(bootstrappingContract.getOperatorsCount() == 1);
        // Then deregister it
        bootstrappingContract.deregisterOperator();
        assertTrue(bootstrappingContract.getOperatorsCount() == 0);
        vm.stopPrank();
    }

    function test04_DeregisterOperator_NotRegistered() public {
        address addr = address(0x7);
        vm.startPrank(addr);
        vm.expectRevert("Operator not registered");
        bootstrappingContract.deregisterOperator();
        vm.stopPrank();
    }

    function test05_ReplaceKey() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        assertTrue(bootstrappingContract.getOperatorsCount() == 0);
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        bytes32 oldKey =
            bytes32(0x440eeb74aa733f646fbe53e0e26c1659b4e2f081e9cbe0163521380eebb93771);
        bootstrappingContract.registerOperator(
            oldKey, addr, "operator4", commission
        );
        assertTrue(bootstrappingContract.getOperatorsCount() == 1);
        (, bytes32 consensusPublicKey, , , ) = bootstrappingContract.operators(addr);
        assertTrue(consensusPublicKey == oldKey);
        // Then change the key
        bytes32 newKey =
            bytes32(0xd995b7f4b2178b0466cfa512955ce2299a4487ebcd86f817d686880dd2b7c4b0);
        bootstrappingContract.replaceKey(newKey);
        (, consensusPublicKey, , , ) = bootstrappingContract.operators(addr);
        assertTrue(consensusPublicKey == newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseByOther() public {
        test03_RegisterOperator();
        // Then change the key
        vm.startPrank(addrs[0]);
        bytes32 newKey =
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrappingContract.replaceKey(newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseBySelf() public {
        test03_RegisterOperator();
        // Then change the key for the same address
        vm.startPrank(addrs[1]);
        bytes32 newKey =
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrappingContract.replaceKey(newKey);
        vm.stopPrank();
    }

    function test06_UpdateOperatorParams() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        bytes32 oldKey =
            bytes32(0x440eeb74aa733f646fbe53e0e26c1659b4e2f081e9cbe0163521380eebb93771);
        bootstrappingContract.registerOperator(
            oldKey, addr, "operator4", commission
        );
        assertTrue(bootstrappingContract.getOperatorsCount() == 1);
        (, , address exocoreAddress, , ) =
            bootstrappingContract.operators(addr);
        assertTrue(exocoreAddress == addr);
        // Change commission, exocoreAddress and website
        bootstrappingContract.updateOperatorExocoreAddress(address(0x8));
        (, , exocoreAddress, , ) = bootstrappingContract.operators(addr);
        assertTrue(exocoreAddress == address(0x8));
        vm.stopPrank();
    }

    function test06_UpdateOperatorParams_Unregistered() public {
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        vm.expectRevert("Operator not registered");
        bootstrappingContract.updateOperatorExocoreAddress(addr);
        vm.stopPrank();
    }

    function test06_UpdateOperatorParams_ExocoreZeroAddress() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        bytes32 key =
            bytes32(0x440eeb74aa733f646fbe53e0e26c1659b4e2f081e9cbe0163521380eebb93771);
        bootstrappingContract.registerOperator(
            key, addr, "operator4", commission
        );
        vm.expectRevert("Exocore address cannot be zero");
        bootstrappingContract.updateOperatorExocoreAddress(address(0));
        vm.stopPrank();
    }

    function test07_AddSupportedToken() public {
        // any address can deploy the token
        vm.startPrank(address(0x1));
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        address cloneAddress = address(myTokenClone);
        vm.stopPrank();
        // only the owner can add the token to the supported list
        vm.startPrank(deployer);
        bootstrappingContract.addSupportedToken(cloneAddress);
        vm.stopPrank();
        // finally, check
        bool isSupported = bootstrappingContract.isTokenSupported(cloneAddress);
        assertTrue(isSupported);
    }

    function test07_AddSupportedToken_AlreadySupported() public {
        vm.startPrank(deployer);
        vm.expectRevert("Token already supported");
        bootstrappingContract.addSupportedToken(address(myToken));
        vm.stopPrank();
    }

    function test08_SetOffsetTime() public {
        assertTrue(bootstrappingContract.offsetTime() == 30 minutes);
        uint256 newOffsetTime = 60 minutes;
        vm.startPrank(deployer);
        bootstrappingContract.setOffsetTime(newOffsetTime);
        vm.stopPrank();
        uint256 offsetTimeInContract = bootstrappingContract.offsetTime();
        assertTrue(offsetTimeInContract == newOffsetTime);
    }

    function test09_DelegateToOperator() public {
        // first, register the operators
        test03_RegisterOperator();
        // then, make the transfers and deposits
        test02_Deposit();
        // first, self delegate
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            bootstrappingContract.delegateToOperator(
                addrs[i], address(myToken), amounts[i]
            );
            vm.stopPrank();
        }
        // finally, delegate from stakers to the operators
        uint8[3][3] memory delegations = [
            [8, 9, 0],
            [0, 7, 8],
            [2, 0, 6]
        ];
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i + 3]);
            for(uint256 j = 0; j < 3; j++) {
                if (delegations[i][j] != 0) {
                    bootstrappingContract.delegateToOperator(
                        addrs[j], address(myToken),
                        uint256(delegations[i][j]) * 10 ** 18
                    );
                }
            }
            vm.stopPrank();
        }
        // nwo validate the delegations, first for operators
        for (uint256 i = 0; i < 3; i++) {
            uint256 amount = bootstrappingContract.delegations(
                addrs[i], addrs[i], address(myToken)
            );
            assertTrue(amount == amounts[i]);
        }
        // then for delegators
        for (uint256 i = 0; i < 1; i++) {
            address delegator = addrs[i + 3];
            for (uint256 j = 0; j < 1; j++) {
                address operator = addrs[j];
                uint256 amount = bootstrappingContract.delegations(
                    delegator, operator, address(myToken)
                );
                assertTrue(amount == uint256(delegations[i][j]) * 10 ** 18);
            }
        }
    }

    function test09_DelegateToOperator_Unregistered() public {
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Operator not registered");
        bootstrappingContract.delegateToOperator(
            addrs[0], address(myToken), amounts[0]
        );
    }

    function test09_DelegateToOperator_UnsupportedToken() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Token not supported");
        bootstrappingContract.delegateToOperator(
            addrs[0], address(0xa), amounts[0]
        );
    }

    function test09_DelegateToOperator_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Delegation amount must be greater than zero");
        bootstrappingContract.delegateToOperator(
            addrs[0], address(myToken), 0
        );
    }

    function test09_DelegateToOperator_NoDeposits() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Insufficient available funds");
        bootstrappingContract.delegateToOperator(
            addrs[0], address(myToken), amounts[0]
        );
    }

    function test09_DelegateToOperator_Excess() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Insufficient available funds");
        bootstrappingContract.delegateToOperator(
            addrs[0], address(myToken), amounts[0] + 1
        );
    }

    function test10_UndelegateFromOperator() public {
        test09_DelegateToOperator();
        // now, undelegate for operators
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            bootstrappingContract.undelegateFromOperator(
                addrs[i], address(myToken), amounts[i]
            );
            vm.stopPrank();
        }
        // finally, validate the undelegations
        for (uint256 i = 0; i < 3; i++) {
            uint256 amount = bootstrappingContract.delegations(
                addrs[i], addrs[i], address(myToken)
            );
            assertTrue(amount == 0);
        }
        // next, for stakers
        uint8[3][3] memory delegations = [
            [8, 9, 0],
            [0, 7, 8],
            [2, 0, 6]
        ];
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i + 3]);
            for(uint256 j = 0; j < 3; j++) {
                if (delegations[i][j] != 0) {
                    bootstrappingContract.undelegateFromOperator(
                        addrs[j], address(myToken),
                        uint256(delegations[i][j]) * 10 ** 18
                    );
                }
            }
            vm.stopPrank();
        }
        // finally, validate the undelegations
        for (uint256 i = 0; i < 3; i++) {
            address delegator = addrs[i + 3];
            for (uint256 j = 0; j < 3; j++) {
                address operator = addrs[j];
                uint256 amount = bootstrappingContract.delegations(
                    delegator, operator, address(myToken)
                );
                assertTrue(amount == 0);
            }
        }
    }

    function test10_UndelegateFromOperator_Unregistered() public {
        test09_DelegateToOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Operator not registered");
        bootstrappingContract.undelegateFromOperator(
            addrs[4], address(myToken), amounts[0]
        );
    }

    function test10_UndelegateFromOperator_UnsupportedToken() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Token not supported");
        bootstrappingContract.undelegateFromOperator(
            addrs[0], address(0xa), amounts[0]
        );
    }

    function test10_UndelegateFromOperator_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Undelegation amount must be greater than zero");
        bootstrappingContract.undelegateFromOperator(
            addrs[0], address(myToken), 0
        );
    }

    function test10_UndelegateFromOperator_Excess() public {
        test09_DelegateToOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Undelegation amount exceeds delegation");
        bootstrappingContract.undelegateFromOperator(
            addrs[0], address(myToken), amounts[0] + 1
        );
    }

    function test10_UndelegateFromOperator_NoDelegation() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Undelegation amount exceeds delegation");
        bootstrappingContract.undelegateFromOperator(
            addrs[0], address(myToken), amounts[0]
        );
    }

    function test11_Withdraw() public {
        // delegate and then undelegate
        test10_UndelegateFromOperator();
        // now, withdraw
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            uint256 before = myToken.balanceOf(addrs[i]);
            (uint256 deposit, ) = bootstrappingContract.userDeposits(addrs[i], address(myToken));
            bootstrappingContract.withdraw(address(myToken), amounts[i]);
            uint256 afterB = myToken.balanceOf(addrs[i]);
            assertTrue(afterB == before + deposit);
            vm.stopPrank();
        }
    }

    function test11_Withdraw_UnsupportedToken() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Token not supported");
        bootstrappingContract.withdraw(address(0xa), amounts[0]);
        vm.stopPrank();
    }

    function test11_Withdraw_ZeroAmount() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Withdrawal amount must be greater than zero");
        bootstrappingContract.withdraw(address(myToken), 0);
        vm.stopPrank();
    }

    function test11_Withdraw_NoDeposits() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Insufficient available funds");
        bootstrappingContract.withdraw(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test11_Withdraw_Excess() public {
        test10_UndelegateFromOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Insufficient available funds");
        bootstrappingContract.withdraw(address(myToken), amounts[0] + 1);
        vm.stopPrank();
    }

    function test12_MarkBootstrapped() public {
        vm.warp(block.timestamp + 1 hours);
        vm.startPrank(address(0x20));
        bootstrappingContract.markBootstrapped();
        vm.stopPrank();
        assertTrue(bootstrappingContract.bootstrapped());
    }

    function test12_MarkBootstrapped_NotTime() public {
        vm.startPrank(address(0x20));
        vm.expectRevert("Spawn time not reached");
        bootstrappingContract.markBootstrapped();
        vm.stopPrank();
    }

    function test12_MarkBootstrapped_AlreadyBootstrapped() public {
        test12_MarkBootstrapped();
        vm.startPrank(address(0x20));
        vm.expectRevert("Contract already bootstrapped");
        bootstrappingContract.markBootstrapped();
        vm.stopPrank();
    }

    function test12_MarkBootstrapped_WrongAddress() public {
        vm.warp(block.timestamp + 1 hours);
        vm.startPrank(address(0x21));
        vm.expectRevert("Only the bootstrapping address can call this function");
        bootstrappingContract.markBootstrapped();
        vm.stopPrank();
    }

    function test13_OperationAllowed() public {
        vm.warp(spawnTime - offsetTime);
        vm.startPrank(addrs[0]);
        vm.expectRevert("Operations are locked");
        bootstrappingContract.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test14_IsCommissionValid() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1e18);
        assertTrue(bootstrappingContract.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateLarge() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(1.1e18, 1e18, 1e18);
        assertFalse(bootstrappingContract.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxRateLarge() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1.1e18, 1e18);
        assertFalse(bootstrappingContract.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateLarge() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0, 1e18, 1.1e18);
        assertFalse(bootstrappingContract.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateExceedsMaxRate() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0.5e18, 0.2e18, 1e18);
        assertFalse(bootstrappingContract.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateExceedsMaxRate() public {
        Bootstrapping.Commission memory commission = Bootstrapping.Commission(0.1e18, 0.2e18, 1e18);
        assertFalse(bootstrappingContract.isCommissionValid(commission));
    }
}
