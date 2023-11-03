pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../src/core/ClientChainGateway.sol";
import "../src/core/Vault.sol";
import "../src/core/ExocoreReceiver.sol";
import "@layerzero-contracts/mocks/LZEndpointMock.sol";

contract ExocoreDeployer {
    function deploy() internal {
        uint16 ExocoreChainID = 0;
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        ERC20PresetFixedSupply weth = new ERC20PresetFixedSupply(
            "weth",
            "WETH",
            1e16,
            address(this)
        );

        address[] memory whitelistTokens = new address[](1);
        whitelistTokens[0] = address(weth);

        Gateway gateway = new Gateway();
        TransparentUpgradeableProxy proxiedGateway = new TransparentUpgradeableProxy(address(gateway), address(proxyAdmin), "");

        Vault vault = new Vault();
        TransparentUpgradeableProxy proxiedVault = new TransparentUpgradeableProxy(address(vault), address(proxyAdmin), "");

        ExocoreReceiver exocoreReceiver = new ExocoreReceiver();
        TransparentUpgradeableProxy proxiedExocoreReceiver = new TransparentUpgradeableProxy(address(exocoreReceiver), address(proxyAdmin), "");

        LZEndpointMock lzEndpoint = new LZEndpointMock(ExocoreChainID);

        Gateway(address(proxiedGateway)).initialize(whitelistTokens, ExocoreChainID, address(proxiedExocoreReceiver), payable(address(this)));
        Vault(address(proxiedVault)).initialize(address(weth), address(proxiedGateway));
        ExocoreReceiver(address(proxiedExocoreReceiver)).initialize(address(lzEndpoint));

    }
}