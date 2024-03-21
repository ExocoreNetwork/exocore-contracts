pragma solidity ^0.8.19;

import "../src/interfaces/IClientChainGateway.sol";
import "../src/interfaces/IVault.sol";
import "../src/interfaces/IExocoreGateway.sol";
import {ERC20PresetFixedSupply} from "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";
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
    ERC20PresetFixedSupply restakeToken;

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

        clientChainRPCURL = vm.envString("SEPOLIA_RPC");
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
    }
}
