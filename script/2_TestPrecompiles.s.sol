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
import "../src/mock/PrecompileCallerMock.sol";

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
        // uint256 exocore = vm.createSelectFork(exocoreRPCURL);

        vm.startBroadcast(exocoredeployer.privateKey);
        // PrecompileCallerMock caller = new PrecompileCallerMock();
        // console.log(address(caller));
        PrecompileCallerMock caller = PrecompileCallerMock(address(0x7445043428567D6A3f60fB12e4832b9446e5FcE6));
        caller.deposit(uint256(1234));

        uint256 balance = caller.balance();
        bool status = caller.lastDepositStatus();
        assertEq(balance, uint256(1234));
        assertEq(status, true);
    }
}
