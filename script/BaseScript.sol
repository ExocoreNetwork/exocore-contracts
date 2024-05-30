pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IExocoreGateway.sol";
import "../src/interfaces/IExoCapsule.sol";
import "../src/core/BeaconProxyBytecode.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/interfaces/precompiles/IClaimReward.sol";

import {IERC20, ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
import "@beacon-oracle/contracts/src/EigenLayerBeaconOracle.sol";
import {IBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import "forge-std/Script.sol";

contract BaseScript is Script {
    struct Player {
        uint256 privateKey;
        address addr;
    }

    Player deployer;
    Player exocoreValidatorSet;
    Player exocoreGenesis;
    Player depositor;
    Player relayer;

    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    address[] vaults;

    IClientChainGateway clientGateway;
    IVault vault;
    IExocoreGateway exocoreGateway;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    EigenLayerBeaconOracle beaconOracle;
    ERC20PresetFixedSupply restakeToken;
    IVault vaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    address delegationMock;
    address depositMock;
    address withdrawMock;
    address claimRewardMock;

    uint256 clientChain;
    uint256 exocore;

    uint16 constant exocoreChainId = 40259;
    uint16 constant clientChainId = 40161;

    address constant sepoliaEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address constant exocoreEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address erc20TokenAddress = 0x83E6850591425e3C1E263c054f4466838B9Bd9e4;

    uint256 constant DEPOSIT_AMOUNT = 1 ether;
    uint256 constant WITHDRAW_AMOUNT = 1 ether;

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

        clientChainRPCURL = vm.envString("HOLESKY_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
    }

    function _deployBeaconOracle() internal returns (EigenLayerBeaconOracle) {
        uint256 GENESIS_BLOCK_TIMESTAMP;

        if (block.chainid == 1) {
            GENESIS_BLOCK_TIMESTAMP = 1606824023;
        } else if (block.chainid == 5) {
            GENESIS_BLOCK_TIMESTAMP = 1616508000;
        } else if (block.chainid == 11155111) {
            GENESIS_BLOCK_TIMESTAMP = 1655733600;
        } else if (block.chainid == 17000) {
            GENESIS_BLOCK_TIMESTAMP = 1695902400;
        } else {
            revert("Unsupported chainId.");
        }

        EigenLayerBeaconOracle oracle = new EigenLayerBeaconOracle(GENESIS_BLOCK_TIMESTAMP);
        return oracle;
    }

    function _bindPrecompileMocks() internal {
        // bind precompile mock contracts code to constant precompile address so that local simulation could pass
        bytes memory DepositMockCode = vm.getDeployedCode("DepositWithdrawMock.sol");
        vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, DepositMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawPrincipleMockCode = vm.getDeployedCode("DepositWithdrawMock.sol");
        vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, WithdrawPrincipleMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }

    function _topUpPlayer(uint256 chain, address token, Player memory provider, address recipient, uint256 targetBalance) internal {
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
