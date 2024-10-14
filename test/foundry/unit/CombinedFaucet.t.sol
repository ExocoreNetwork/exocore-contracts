// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CombinedFaucet} from "../../../src/core/CombinedFaucet.sol";
import {ERC20PresetMinterPauser} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";
import "forge-std/Test.sol"; // For mock ERC20 token

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract BaseFaucetTest is Test {

    CombinedFaucet public faucet;
    address public owner;
    address public user1;
    address public user2;

    uint256 public tokenAmount = 1 ether; // Amount to be distributed in each request

    function setUp() public virtual {
        // Initialize the test environment
        owner = address(0x3);
        user1 = address(0x1);
        user2 = address(0x2);
    }

    function _deploy(address token) internal {
        // Deploy the faucet and initialize it
        address proxyAdmin = address(new ProxyAdmin());
        CombinedFaucet faucetLogic = new CombinedFaucet();
        faucet = CombinedFaucet(
            payable(address(new TransparentUpgradeableProxy(address(faucetLogic), address(proxyAdmin), "")))
        );
        faucet.initialize(owner, token, tokenAmount);
    }

}

// case of ERC20 faucet, separate from native token faucet
contract ERC20FaucetTest is BaseFaucetTest {

    ERC20PresetMinterPauser public token;

    function setUp() public override {
        super.setUp();
        // Deploy a mock ERC20 token
        token = new ERC20PresetMinterPauser("Test Token", "TST");
        token.mint(owner, tokenAmount * 10);
        token.mint(user1, tokenAmount);

        _deploy(address(token));

        // Mint tokens to the faucet
        token.mint(address(faucet), tokenAmount * 5);
    }

    function testInitialization() public {
        // Check if the initialization is correct
        assertEq(faucet.tokenAmount(), tokenAmount);
        assertEq(faucet.token(), address(token));
    }

    function testRequestTokens() public {
        // Initial token balance of user1 should be `tokenAmount` TST
        assertEq(token.balanceOf(user1), tokenAmount);

        // Simulate user1 requesting tokens from the faucet
        vm.prank(user1);
        faucet.requestTokens();

        // Check if the tokens were transferred
        assertEq(token.balanceOf(user1), tokenAmount * 2);
        assertEq(token.balanceOf(address(faucet)), tokenAmount * 4);

        // Ensure 24h rate limit is enforced
        vm.expectRevert("CombinedFaucet: Rate limit exceeded. Please wait 24 hours.");
        vm.prank(user1);
        faucet.requestTokens();
    }

    function testRateLimit() public {
        // Request tokens for the first time
        vm.prank(user1);
        faucet.requestTokens();

        // Try again before 24 hours have passed
        vm.expectRevert("CombinedFaucet: Rate limit exceeded. Please wait 24 hours.");
        vm.prank(user1);
        faucet.requestTokens();

        // Fast forward time by 24 hours
        vm.warp(block.timestamp + 1 days);

        // Should work now
        vm.prank(user1);
        faucet.requestTokens();
        assertEq(token.balanceOf(user1), tokenAmount * 3);
    }

    function testOnlyOwnerCanSetTokenAddress() public {
        // Try setting the token address as a non-owner
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        faucet.setTokenAddress(address(0xdead));

        // Set the token address as the owner
        vm.prank(owner);
        faucet.setTokenAddress(address(0xdead));
        assertEq(faucet.token(), address(0xdead));
    }

    function testOnlyOwnerCanSetTokenAmount() public {
        // Try setting the token amount as a non-owner
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        faucet.setTokenAmount(50 ether);

        // Set the token amount as the owner
        vm.prank(owner);
        faucet.setTokenAmount(50 ether);
        assertEq(faucet.tokenAmount(), 50 ether);
    }

    function testPauseUnpause() public {
        // Pause the contract as the owner
        vm.prank(owner);
        faucet.pause();
        assertEq(faucet.paused(), true);

        // Try requesting tokens while paused
        vm.prank(user1);
        vm.expectRevert("Pausable: paused");
        faucet.requestTokens();

        // Unpause the contract
        vm.prank(owner);
        faucet.unpause();
        assertEq(faucet.paused(), false);

        // Request tokens should work now
        vm.prank(user1);
        faucet.requestTokens();
        assertEq(token.balanceOf(user1), tokenAmount * 2);
    }

    function testRecoverTokens() public {
        // Initially, owner has 10 * `tokenAmount` TST tokens
        assertEq(token.balanceOf(owner), tokenAmount * 10);

        // Call recoverTokens as the owner
        vm.prank(owner);
        faucet.recoverTokens(address(token), tokenAmount);

        // Owner should recover `tokenAmount` TST tokens
        assertEq(token.balanceOf(owner), tokenAmount * 11);
    }

    function testCannotWithdrawNativeTokens() public {
        // Try withdrawing native tokens from the faucet
        vm.expectRevert("CombinedFaucet: only for native tokens");
        vm.prank(owner);
        faucet.withdraw(user1);
    }

    function testRejectERC721() public {
        // Try sending an ERC721 token, it should revert
        vm.expectRevert("Faucet: ERC721 tokens not accepted");
        vm.prank(user1);
        faucet.onERC721Received(user1, user2, 1, "");
    }

}

// case of native token faucet, separate from ERC20 faucet
contract NativeTokenFaucetTest is BaseFaucetTest {

    function setUp() public override {
        super.setUp();
        vm.deal(owner, tokenAmount * 10);
        _deploy(address(0));
        vm.deal(address(faucet), tokenAmount * 5);
    }

    function testInitialization() public {
        // Check if the initialization is correct
        assertEq(faucet.tokenAmount(), tokenAmount);
        assertEq(faucet.token(), address(0));
    }

    function testRequestTokens() public {
        // Initial token balance of user1 should be 0
        assertEq(user1.balance, 0);

        // Simulate user1 requesting tokens from the faucet
        vm.prank(owner);
        faucet.withdraw(user1);

        // Check if the tokens were transferred
        assertEq(user1.balance, tokenAmount * 1);
        assertEq(address(faucet).balance, tokenAmount * 4);

        // Ensure 24h rate limit is enforced
        vm.expectRevert("CombinedFaucet: Rate limit exceeded. Please wait 24 hours.");
        vm.prank(owner);
        faucet.withdraw(user1);
    }

    function testOnlyOwnerCanRequestTokens() public {
        // Try requesting tokens as a non-owner
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        faucet.withdraw(user1);

        // Request tokens as the owner
        vm.prank(owner);
        faucet.withdraw(user1);
        assertEq(user1.balance, tokenAmount);
    }

    function testCannotRequestNativeTokens() public {
        // Try requesting tokens from the faucet
        vm.expectRevert("CombinedFaucet: not for native tokens");
        vm.prank(owner);
        faucet.requestTokens();
    }

    function testRateLimit() public {
        // Request tokens for the first time
        vm.prank(owner);
        faucet.withdraw(user1);

        // Try again before 24 hours have passed
        vm.expectRevert("CombinedFaucet: Rate limit exceeded. Please wait 24 hours.");
        vm.prank(owner);
        faucet.withdraw(user1);

        // Fast forward time by 24 hours
        vm.warp(block.timestamp + 1 days);

        // Should work now
        vm.prank(owner);
        faucet.withdraw(user1);
        assertEq(user1.balance, tokenAmount * 2);
    }

    function testOnlyOwnerCanSetTokenAddress() public {
        // Try setting the token address as a non-owner
        vm.deal(user1, 1 ether); // for gas
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        faucet.setTokenAddress(address(0xdead));

        // Set the token address as the owner
        vm.prank(owner);
        faucet.setTokenAddress(address(0xdead));
        assertEq(faucet.token(), address(0xdead));
    }

    function testOnlyOwnerCanSetTokenAmount() public {
        // Try setting the token amount as a non-owner
        vm.prank(user1);
        vm.expectRevert("Ownable: caller is not the owner");
        faucet.setTokenAmount(50 ether);

        // Set the token amount as the owner
        vm.prank(owner);
        faucet.setTokenAmount(50 ether);
        assertEq(faucet.tokenAmount(), 50 ether);
    }

    function testPauseUnpause() public {
        // Pause the contract as the owner
        vm.prank(owner);
        faucet.pause();
        assertEq(faucet.paused(), true);

        // Try requesting tokens while paused
        vm.prank(owner);
        vm.expectRevert("Pausable: paused");
        faucet.withdraw(user1);

        // Unpause the contract
        vm.prank(owner);
        faucet.unpause();
        assertEq(faucet.paused(), false);

        // Request tokens should work now
        vm.prank(owner);
        faucet.withdraw(user1);
        assertEq(user1.balance, tokenAmount);
    }

    function testRecoverTokens() public {
        // Initially, owner has 10 * `tokenAmount` native tokens
        assertEq(owner.balance, tokenAmount * 10);
        assertEq(address(faucet).balance, tokenAmount * 5);

        // Call recoverTokens as the owner
        vm.prank(owner);
        faucet.recoverTokens(address(0), tokenAmount);

        // Owner should recover `tokenAmount` native tokens
        assertEq(owner.balance, tokenAmount * 11);
        assertEq(address(faucet).balance, tokenAmount * 4);
    }

    function testRejectERC721() public {
        // Try sending an ERC721 token, it should revert
        vm.expectRevert("Faucet: ERC721 tokens not accepted");
        vm.prank(user1);
        faucet.onERC721Received(user1, user2, 1, "");
    }

}
