pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "@safe-contracts/proxies/GnosisSafeProxyFactory.sol";
import "@safe-contracts/GnosisSafe.sol";

contract CreateMultisigScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Load deployed contract addresses
        GnosisSafeProxyFactory proxyFactory = GnosisSafeProxyFactory(0xd92Eb22d59D2736C12ef8e009833b98dB812BC5F);
        GnosisSafe safeSingleton = GnosisSafe(payable(0xE28848a95D96dFc200A48f976b32B726253a8e14));

        // Set up owners (replace with actual addresses)
        address[] memory owners = new address[](3);
        owners[0] = address(0x1111111111111111111111111111111111111111);
        owners[1] = address(0x2222222222222222222222222222222222222222);
        owners[2] = address(0x3333333333333333333333333333333333333333);

        // Set up Safe parameters
        uint256 threshold = 2;
        address to = address(0);
        bytes memory data = "";
        address fallbackHandler = 0x820ed29524601172Fe4aec900Bc48432067CBCDF; // CompatibilityFallbackHandler
        address paymentToken = address(0);
        uint256 payment = 0;
        address payable paymentReceiver = payable(address(0));

        // Encode initialization data
        bytes memory initializer = abi.encodeWithSelector(
            GnosisSafe.setup.selector,
            owners,
            threshold,
            to,
            data,
            fallbackHandler,
            paymentToken,
            payment,
            paymentReceiver
        );

        // Create new Safe proxy
        GnosisSafeProxy safeProxy = proxyFactory.createProxy(address(safeSingleton), initializer);

        console.log("New Safe created at:", address(safeProxy));

        vm.stopBroadcast();
    }
}
