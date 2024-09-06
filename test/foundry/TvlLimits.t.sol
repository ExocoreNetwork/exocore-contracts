pragma solidity ^0.8.19;

import "../../src/core/ExoCapsule.sol";
import "../../src/core/ExocoreGateway.sol";

import {IExoCapsule} from "../../src/interfaces/IExoCapsule.sol";
import {ILSTRestakingController} from "../../src/interfaces/ILSTRestakingController.sol";

import "../../src/storage/GatewayStorage.sol";
import "./ExocoreDeployer.t.sol";
import "forge-std/Test.sol";

import "@layerzero-v2/protocol/contracts/libs/AddressCast.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract TvlLimitsTest is ExocoreDeployer {

    function test_UpdateTvlLimits() public {
        test_AddWhitelistTokens();
        IVault vault = clientGateway.tokenToVault(address(restakeToken));
        assertTrue(address(vault) != address(0));
        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(restakeToken);
        uint256[] memory tvlLimits = new uint256[](1);
        tvlLimits[0] = vault.getTvlLimit() * 2; // double the TVL limit
        vm.prank(exocoreValidatorSet.addr);
        clientGateway.updateTvlLimits(whitelistTokens, tvlLimits);
        assertTrue(vault.getTvlLimit() == tvlLimits[0]);
    }

    function test07_UpdateTvlLimits_NotWhitelisted() public {
        test_AddWhitelistTokens();
        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(0xa);
        uint256[] memory tvlLimits = new uint256[](1);
        tvlLimits[0] = 500;
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenNotWhitelisted.selector, whitelistTokens[0]));
        clientGateway.updateTvlLimits(whitelistTokens, tvlLimits);
        vm.stopPrank();
    }

    function test07_UpdateTvlLimits_NativeEth() public {
        test_AddWhitelistTokens();
        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = VIRTUAL_STAKED_ETH_ADDRESS;
        uint256[] memory tvlLimits = new uint256[](1);
        tvlLimits[0] = 500;
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.NoTvlLimitForNativeRestaking.selector);
        clientGateway.updateTvlLimits(whitelistTokens, tvlLimits);
        vm.stopPrank();
    }

    function test08_AddWhitelistTokens_NotPermitted() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(restakeToken);
        uint256[] memory tvlLimits = new uint256[](1);
        tvlLimits[0] = 500;
        vm.startPrank(exocoreValidatorSet.addr);
        vm.expectRevert(Errors.ClientChainGatewayTokenAdditionViaExocore.selector);
        clientGateway.addWhitelistTokens(tokens, tvlLimits);
    }

}
