pragma solidity ^0.8.19;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "../../src/core/ClientChainGateway.sol";
import "../../src/core/Vault.sol";
import "../../src/core/ExocoreGateway.sol";
import "../mocks/NonShortCircuitLzEndpointMock.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";
import "../../src/interfaces/precompiles/IDelegation.sol";
import "../../src/interfaces/precompiles/IDeposit.sol";
import "../../src/interfaces/precompiles/IWithdrawPrinciple.sol";
import "../../src/interfaces/precompiles/IClaimReward.sol";
import "@layerzero-contracts/interfaces/ILayerZeroEndpoint.sol";


contract ExocoreDeployer is Test {
    Player[] players;
    address[] whitelistTokens;
    Player exocoreValidatorSet;
    address[] vaults;
    ERC20PresetFixedSupply restakeToken;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpoint clientChainLzEndpoint;
    ILayerZeroEndpoint exocoreLzEndpoint;

    uint16 exocoreChainId = 0;
    uint16 clientChainId = 1;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    function setUp() public virtual {
        players.push(Player({privateKey: uint256(0x1), addr: vm.addr(uint256(0x1))}));
        players.push(Player({privateKey: uint256(0x2), addr: vm.addr(uint256(0x2))}));
        players.push(Player({privateKey: uint256(0x3), addr: vm.addr(uint256(0x3))}));
        exocoreValidatorSet = Player({privateKey: uint256(0xa), addr: vm.addr(uint256(0xa))});
        
        _deploy();
    }

    function _deploy() internal {
        // prepare outside contracts like ERC20 token contract and layerzero endpoint contract
        restakeToken = new ERC20PresetFixedSupply(
            "rest",
            "rest",
            1e16,
            exocoreValidatorSet.addr
        );
        clientChainLzEndpoint = new NonShortCircuitLzEndpointMock(clientChainId);
        exocoreLzEndpoint = new NonShortCircuitLzEndpointMock(exocoreChainId);

        // deploy and initialize client chain contracts
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        
        whitelistTokens.push(address(restakeToken));
        ClientChainGateway clientGatewayLogic = new ClientChainGateway();
        clientGateway = ClientChainGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(clientGatewayLogic), 
                        address(proxyAdmin), 
                        abi.encodeWithSelector(
                            clientGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            whitelistTokens,
                            address(clientChainLzEndpoint),
                            exocoreChainId
                        )
                    )
                )
            )
        );

        Vault vaultLogic = new Vault();
        vault = Vault(
            address(
                new TransparentUpgradeableProxy(
                    address(vaultLogic), 
                    address(proxyAdmin),
                    abi.encodeWithSelector(
                        vaultLogic.initialize.selector,
                        address(restakeToken),
                        address(clientGateway)
                    )
                )
            )
        );

        // deploy Exocore network contracts
        ExocoreGateway exocoreGatewayLogic = new ExocoreGateway();
        exocoreGateway = ExocoreGateway(
            payable(address(
                    new TransparentUpgradeableProxy(
                        address(exocoreGatewayLogic),
                        address(proxyAdmin), 
                        abi.encodeWithSelector(
                            exocoreGatewayLogic.initialize.selector,
                            payable(exocoreValidatorSet.addr),
                            address(exocoreLzEndpoint)
                        )
                    )
                )
            )
        );

        // set the destination endpoint for corresponding destinations in endpoint mock
        NonShortCircuitLzEndpointMock(address(clientChainLzEndpoint)).setDestLzEndpoint(address(exocoreGateway), address(exocoreLzEndpoint));
        NonShortCircuitLzEndpointMock(address(exocoreLzEndpoint)).setDestLzEndpoint(address(clientGateway), address(clientChainLzEndpoint));
        
        // Exocore validator set should be the owner of gateway contracts and only owner could call these functions.
        vm.startPrank(exocoreValidatorSet.addr);
        // add token vaults to gateway
        vaults.push(address(vault));
        clientGateway.addTokenVaults(vaults);
        // as LzReceivers, gateway should set bytes(sourceChainGatewayAddress+thisAddress) as trusted remote to receive messages
        clientGateway.setTrustedRemote(exocoreChainId, abi.encodePacked(address(exocoreGateway), address(clientGateway)));
        exocoreGateway.setTrustedRemote(clientChainId, abi.encodePacked(address(clientGateway), address(exocoreGateway)));
        vm.stopPrank();

        // bind precompile mock contracts code to constant precompile address
        bytes memory DepositMockCode = vm.getDeployedCode("DepositMock.sol");
        vm.etch(DEPOSIT_PRECOMPILE_ADDRESS, DepositMockCode);

        bytes memory DelegationMockCode = vm.getDeployedCode("DelegationMock.sol");
        vm.etch(DELEGATION_PRECOMPILE_ADDRESS, DelegationMockCode);

        bytes memory WithdrawPrincipleMockCode = vm.getDeployedCode("WithdrawPrincipleMock.sol");
        vm.etch(WITHDRAW_PRECOMPILE_ADDRESS, WithdrawPrincipleMockCode);

        bytes memory WithdrawRewardMockCode = vm.getDeployedCode("ClaimRewardMock.sol");
        vm.etch(CLAIM_REWARD_PRECOMPILE_ADDRESS, WithdrawRewardMockCode);
    }
}