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
        
        exocoreValidatorSet.privateKey = vm.envUint("EXOCORE_VALIDATOR_SET_PRIVATE_KEY");
        exocoreValidatorSet.addr = vm.addr(exocoreValidatorSet.privateKey);
    }

    function run() public {
        vm.startBroadcast(deployer.privateKey);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreLzEndpoint = new NonShortCircuitLzEndpointMock(exocoreChainId);
        vm.stopBroadcast();

        exocoreGateway.initialize(payable(exocoreValidatorSet.addr), address(exocoreLzEndpoint));
    }
}
