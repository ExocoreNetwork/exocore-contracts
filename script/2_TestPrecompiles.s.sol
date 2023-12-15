pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "../src/interfaces/precompiles/IDelegation.sol";
import "../src/interfaces/precompiles/IDeposit.sol";
import "../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../src/mock/NonShortCircuitLzEndpointMock.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";
import "../src/interfaces/precompiles/IDeposit.sol";

contract DeployScript is Script, Test {
    Player exocoredeployer;
    string exocoreRPCURL;
    uint16 clientChainId = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    using stdJson for string;
    
    function setUp() public {
    
        exocoredeployer.privateKey = vm.envUint("EXOCORE_DEPLOYER_PRIVATE_KEY");
        exocoredeployer.addr = vm.addr(exocoredeployer.privateKey);
        console.log("deployer address:", exocoredeployer.addr);

        exocoreRPCURL = vm.envString("EXOCORE_LOCAL_RPC");

    }

    function run() public {
        uint256 exocore = vm.createSelectFork(exocoreRPCURL);

        vm.startBroadcast(exocoredeployer.privateKey);
        (bool success, bytes memory reason) = DEPOSIT_PRECOMPILE_ADDRESS.call(
            abi.encodeWithSelector(
                DEPOSIT_CONTRACT.depositTo.selector,
                uint16(101),
                abi.encodePacked(bytes32(bytes20(address(0xdAC17F958D2ee523a2206206994597C13D831ec7)))),
                abi.encodePacked(bytes32(bytes20(address(0x2)))),
                uint256(1234)
            )
        );
        console.logBytes(reason);

        vm.stopBroadcast();
        assertEq(success, true);
        assertNotEq(reason, bytes("0x"));
    }
}
