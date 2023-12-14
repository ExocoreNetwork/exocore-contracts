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

        exocoreRPCURL = vm.envString("EXOCORE_LOCAL_RPC");

    }

    function run() public {
        uint256 exocore = vm.createSelectFork(exocoreRPCURL);

        vm.startBroadcast(exocoredeployer.privateKey);
        (bool success, uint256 balance) = DEPOSIT_CONTRACT.depositTo(
            uint16(clientChainId),
            abi.encodePacked(bytes32(bytes20(address(0x1)))),
            abi.encodePacked(bytes32(bytes20(address(0x2)))),
            uint256(1234)
        );
        vm.stopBroadcast();
        assertEq(success, true);
        assertEq(balance, uint256(1234));
    }
}
