pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IExoCapsule.sol";
import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IRewardVault.sol";
import "../src/utils/BeaconProxyBytecode.sol";
import "../src/utils/CustomProxyAdmin.sol";

import "../src/interfaces/precompiles/IAssets.sol";
import "../src/interfaces/precompiles/IReward.sol";
import "../src/interfaces/precompiles/IDelegation.sol";

import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import {ERC20PresetFixedSupply, IERC20} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "forge-std/Script.sol";
import {StdCheats} from "forge-std/StdCheats.sol";

import "../test/mocks/AssetsMock.sol";
import "../test/mocks/RewardMock.sol";
import "../test/mocks/DelegationMock.sol";

contract BaseScript is Script, StdCheats {

    struct Player {
        uint256 privateKey;
        address addr;
    }

    Player deployer;
    Player exocoreValidatorSet;
    Player exocoreGenesis;
    Player depositor;
    Player relayer;

    string sepoliaRPCURL;
    string holeskyRPCURL;
    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    uint256[] tvlLimits;

    IClientChainGateway clientGateway;
    IVault vault;
    IRewardVault rewardVault;
    IExocoreGateway exocoreGateway;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    EigenLayerBeaconOracle beaconOracle;
    ERC20PresetFixedSupply restakeToken;
    IVault vaultImplementation;
    IRewardVault rewardVaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon rewardVaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;
    CustomProxyAdmin clientChainProxyAdmin;

    address delegationMock;
    address assetsMock;
    address rewardMock;

    uint256 clientChain;
    uint256 exocore;

    uint16 constant exocoreChainId = 40_259;
    uint16 constant clientChainId = 40_161;

    address constant sepoliaEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address constant exocoreEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address erc20TokenAddress = 0x83E6850591425e3C1E263c054f4466838B9Bd9e4;

    uint256 constant DEPOSIT_AMOUNT = 1 ether;
    uint256 constant WITHDRAW_AMOUNT = 1 ether;
    address internal constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 internal constant TOKEN_ADDRESS_BYTES_LENGTH = 32;

    bool useExocorePrecompileMock;
    bool useEndpointMock;

    function setUp() public virtual {
        deployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        deployer.addr = vm.addr(deployer.privateKey);

        exocoreValidatorSet.privateKey = vm.envUint("TEST_ACCOUNT_THREE_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);

        exocoreGenesis.privateKey = vm.envUint("EXOCORE_GENESIS_PRIVATE_KEY");
        exocoreGenesis.addr = vm.addr(exocoreGenesis.privateKey);

        depositor.privateKey = vm.envUint("TEST_ACCOUNT_FOUR_PRIVATE_KEY");
        depositor.addr = vm.addr(depositor.privateKey);

        relayer.privateKey = vm.envUint("TEST_ACCOUNT_FOUR_PRIVATE_KEY");
        relayer.addr = vm.addr(relayer.privateKey);

        useEndpointMock = vm.envBool("USE_ENDPOINT_MOCK");
        console.log("NOTICE: using l0 endpoint mock", useEndpointMock);
        useExocorePrecompileMock = vm.envBool("USE_EXOCORE_PRECOMPILE_MOCK");
        console.log("NOTICE: using exocore precompiles mock", useExocorePrecompileMock);

        clientChainRPCURL = vm.envString("CLIENT_CHAIN_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
    }

    function _deployBeaconOracle() internal returns (EigenLayerBeaconOracle) {
        uint256 GENESIS_BLOCK_TIMESTAMP;

        if (block.chainid == 1) {
            GENESIS_BLOCK_TIMESTAMP = 1_606_824_023;
        } else if (block.chainid == 5) {
            GENESIS_BLOCK_TIMESTAMP = 1_616_508_000;
        } else if (block.chainid == 11_155_111) {
            GENESIS_BLOCK_TIMESTAMP = 1_655_733_600;
        } else if (block.chainid == 17_000) {
            GENESIS_BLOCK_TIMESTAMP = 1_695_902_400;
        } else {
            revert("Unsupported chainId.");
        }

        EigenLayerBeaconOracle oracle = new EigenLayerBeaconOracle(GENESIS_BLOCK_TIMESTAMP);
        return oracle;
    }

    function _bindPrecompileMocks() internal {
        uint256 previousFork = type(uint256).max;
        try vm.activeFork() returns (uint256 forkId) {
            previousFork = forkId;
        } catch {
            // ignore
        }
        // choose the fork to ensure no client chain simulation is impacted
        vm.selectFork(exocore);
        // even with --skip-simulation, some transactions fail. this helps work around that limitation
        // but it isn't perfect. if you face too much trouble, try calling the function(s) directly
        // with cast or remix.
        deployCodeTo("AssetsMock.sol", abi.encode(clientChainId), ASSETS_PRECOMPILE_ADDRESS);
        deployCodeTo("DelegationMock.sol", DELEGATION_PRECOMPILE_ADDRESS);
        deployCodeTo("RewardMock.sol", REWARD_PRECOMPILE_ADDRESS);
        // go to the original fork, if one was selected
        if (previousFork != type(uint256).max) {
            vm.selectFork(previousFork);
        }
    }

    function _topUpPlayer(
        uint256 chain,
        address token,
        Player memory provider,
        address recipient,
        uint256 targetBalance
    ) internal {
        vm.selectFork(chain);
        vm.startBroadcast(provider.privateKey);

        if (token == address(0)) {
            if (recipient.balance < targetBalance) {
                (bool sent,) = recipient.call{value: targetBalance - recipient.balance}("");
                require(sent, "Failed to send Ether");
            }
        } else {
            uint256 currentBalance = IERC20(token).balanceOf(recipient);
            if (currentBalance < targetBalance) {
                IERC20(token).transfer(recipient, targetBalance - currentBalance);
            }
        }
        vm.stopBroadcast();
    }

}
