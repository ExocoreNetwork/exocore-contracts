pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../../test/mocks/Faucet.sol";

contract DeployScript is Script {
    Player deployer;
    struct Player {
        uint256 privateKey;
        address addr;
    }
    
    function setUp() public {
        deployer.privateKey = vm.envUint("EXOCORE_DEPLOYER_PRIVATE_KEY");
        deployer.addr = vm.addr(deployer.privateKey);
    }

    function run() public {
        vm.startBroadcast(deployer.privateKey);
        Faucet faucet = new Faucet();
        vm.stopBroadcast();
    }
}
