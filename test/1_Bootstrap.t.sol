// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/core/Bootstrapping.sol";
import "../src/core/MyToken.sol";

contract BootstrappingTest is Test {
    MyToken myToken;
    BootstrappingContract bootstrappingContract;
    address[] addrs = new address[](6);
    uint256[] amounts = [35 * 10 ** 18, 25 * 10 ** 18, 10 * 10 ** 18, 17 * 10 ** 18, 15 * 10 ** 18, 8 * 10 ** 18];

    function setUp() public {
        myToken = new MyToken(1000000 * 10 ** 18);
        addrs[0] = address(0x1); // Simulated OPERATOR1 address
        addrs[1] = address(0x2); // Simulated OPERATOR2 address
        addrs[2] = address(0x3); // Simulated OPERATOR3 address
        addrs[3] = address(0x4); // Simulated STAKER1 address
        addrs[4] = address(0x5); // Simulated STAKER2 address
        addrs[5] = address(0x6); // Simulated STAKER3 address

        address[] memory tokenAddresses = new address[](1);
        tokenAddresses[0] = address(myToken);
        uint256 spawnTime = block.timestamp + 1 hours;
        uint256 offsetTime = 30 minutes;
        bootstrappingContract = new BootstrappingContract(tokenAddresses, spawnTime, offsetTime);
    }

    function testDeposits() public {
        // Distribute MyToken to addresses
        for (uint256 i = 0; i < 6; i++) {
            deal(address(myToken), addrs[i], 1000 * 10 ** 18);
            myToken.transfer(addrs[i], amounts[i]);
        }

        // Make deposits
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            myToken.approve(address(bootstrappingContract), amounts[i]);
            bootstrappingContract.deposit(address(myToken), amounts[i]);
            vm.stopPrank();
        }
    }

    function testRegisterOperator() public {
        // Register operators
        string[3] memory names = ["operator1", "operator2", "operator3"];
        string[3] memory websites = ["operator1.com", "operator2.com", "operator3.com"];
        // Although it is not needed here, we can convert an operator's
        // bech32 address to hex.
        // exocored keys add --algo eth_secp256k1 MY_KEY --keyring-backend file
        // Then convert it to Eth-compatible version.
        // cast 2a $(exocored keys parse $(exocored keys show -a MY_KEY --keyring-backend file) --output json | jq .bytes)
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            // bootstrappingContract.registerOperator(
            //     consensusPublicKey,
            //     exocoreAddresses[i],
            //     0, names[i], websites[i]
            // );
            vm.stopPrank();
        }
    }

    function testIsTokenSupported() public {
        bool isSupported = bootstrappingContract.isTokenSupported(address(myToken));
        assertTrue(isSupported);
        bool isSupported2 = bootstrappingContract.isTokenSupported(address(0));
        assertFalse(isSupported2);
    }
}
