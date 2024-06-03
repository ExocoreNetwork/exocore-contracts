// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";
import "forge-std/Test.sol";
import {CustomProxyAdmin} from "../../src/core/CustomProxyAdmin.sol";
import {Vault} from "../../src/core/Vault.sol";
import {ClientChainGateway} from "../../src/core/ClientChainGateway.sol";
import {Bootstrap} from "../../src/core/Bootstrap.sol";
import {MyToken} from "./MyToken.sol";
import {NonShortCircuitEndpointV2Mock} from "../mocks/NonShortCircuitEndpointV2Mock.sol";
import {IOperatorRegistry} from "../../src/interfaces/IOperatorRegistry.sol";
import "@openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@layerzerolabs/lz-evm-protocol-v2/contracts/libs/GUID.sol";
import {Origin} from "../../src/lzApp/OAppReceiverUpgradeable.sol";
import {GatewayStorage} from "../../src/storage/GatewayStorage.sol";
import {BootstrapStorage} from "../../src/storage/BootstrapStorage.sol";
import {IBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";
import {UpgradeableBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "src/core/ExoCapsule.sol";
import "src/storage/GatewayStorage.sol";
import "src/core/BeaconProxyBytecode.sol";

contract BootstrapTest is Test {
    MyToken myToken;
    MyToken appendedToken;
    CustomProxyAdmin proxyAdmin;
    Bootstrap bootstrap;
    address[] addrs = new address[](6);
    uint256[] amounts = [
        35 * 10 ** 18, // self
        25 * 10 ** 18, // self
        10 * 10 ** 18, // self
        17 * 10 ** 18, // 8 + 9 + 0
        15 * 10 ** 18, // 0 + 7 + 8
        8 * 10 ** 18 // 2 + 0 + 6
    ];
    address deployer = address(0xdeadbeef);
    uint256 spawnTime;
    uint256 offsetDuration;
    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;
    address[] whitelistTokens;
    address[] appendedWhitelistTokensForUpgrade;
    NonShortCircuitEndpointV2Mock clientChainLzEndpoint;
    address exocoreValidatorSet = vm.addr(uint256(0x8));
    address undeployedExocoreGateway = vm.addr(uint256(0x9));
    address undeployedExocoreLzEndpoint = vm.addr(uint256(0xb));

    IVault vaultImplementation;
    IExoCapsule capsuleImplementation;
    IBeacon vaultBeacon;
    IBeacon capsuleBeacon;
    BeaconProxyBytecode beaconProxyBytecode;

    bytes constant BEACON_PROXY_BYTECODE =
        hex"608060405260405161090e38038061090e83398101604081905261002291610460565b61002e82826000610035565b505061058a565b61003e83610100565b6040516001600160a01b038416907f1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e90600090a260008251118061007f5750805b156100fb576100f9836001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100c5573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100e99190610520565b836102a360201b6100291760201c565b505b505050565b610113816102cf60201b6100551760201c565b6101725760405162461bcd60e51b815260206004820152602560248201527f455243313936373a206e657720626561636f6e206973206e6f74206120636f6e6044820152641d1c9858dd60da1b60648201526084015b60405180910390fd5b6101e6816001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156101b3573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906101d79190610520565b6102cf60201b6100551760201c565b61024b5760405162461bcd60e51b815260206004820152603060248201527f455243313936373a20626561636f6e20696d706c656d656e746174696f6e206960448201526f1cc81b9bdd08184818dbdb9d1c9858dd60821b6064820152608401610169565b806102827fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d5060001b6102de60201b6100641760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b60606102c883836040518060600160405280602781526020016108e7602791396102e1565b9392505050565b6001600160a01b03163b151590565b90565b6060600080856001600160a01b0316856040516102fe919061053b565b600060405180830381855af49150503d8060008114610339576040519150601f19603f3d011682016040523d82523d6000602084013e61033e565b606091505b5090925090506103508683838761035a565b9695505050505050565b606083156103c65782516103bf576001600160a01b0385163b6103bf5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610169565b50816103d0565b6103d083836103d8565b949350505050565b8151156103e85781518083602001fd5b8060405162461bcd60e51b81526004016101699190610557565b80516001600160a01b038116811461041957600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561044f578181015183820152602001610437565b838111156100f95750506000910152565b6000806040838503121561047357600080fd5b61047c83610402565b60208401519092506001600160401b038082111561049957600080fd5b818501915085601f8301126104ad57600080fd5b8151818111156104bf576104bf61041e565b604051601f8201601f19908116603f011681019083821181831017156104e7576104e761041e565b8160405282815288602084870101111561050057600080fd5b610511836020830160208801610434565b80955050505050509250929050565b60006020828403121561053257600080fd5b6102c882610402565b6000825161054d818460208701610434565b9190910192915050565b6020815260008251806020840152610576816040850160208701610434565b601f01601f19169190910160400192915050565b61034e806105996000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610067565b610100565b565b606061004e83836040518060600160405280602781526020016102f260279139610124565b9392505050565b6001600160a01b03163b151590565b90565b600061009a7fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50546001600160a01b031690565b6001600160a01b0316635c60da1b6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156100d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906100fb9190610249565b905090565b3660008037600080366000845af43d6000803e80801561011f573d6000f35b3d6000fd5b6060600080856001600160a01b03168560405161014191906102a2565b600060405180830381855af49150503d806000811461017c576040519150601f19603f3d011682016040523d82523d6000602084013e610181565b606091505b50915091506101928683838761019c565b9695505050505050565b6060831561020d578251610206576001600160a01b0385163b6102065760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610217565b610217838361021f565b949350505050565b81511561022f5781518083602001fd5b8060405162461bcd60e51b81526004016101fd91906102be565b60006020828403121561025b57600080fd5b81516001600160a01b038116811461004e57600080fd5b60005b8381101561028d578181015183820152602001610275565b8381111561029c576000848401525b50505050565b600082516102b4818460208701610272565b9190910192915050565b60208152600082518060208401526102dd816040850160208701610272565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a2646970667358221220d51e81d3bc5ed20a26aeb05dce7e825c503b2061aa78628027300c8d65b9d89a64736f6c634300080c0033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";

    function setUp() public {
        addrs[0] = address(0x1); // Simulated OPERATOR1 address
        addrs[1] = address(0x2); // Simulated OPERATOR2 address
        addrs[2] = address(0x3); // Simulated OPERATOR3 address
        addrs[3] = address(0x4); // Simulated STAKER1 address
        addrs[4] = address(0x5); // Simulated STAKER2 address
        addrs[5] = address(0x6); // Simulated STAKER3 address

        vm.startPrank(deployer);
        // first deploy the token
        myToken = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        whitelistTokens.push(address(myToken));
        appendedToken = new MyToken("MyToken2", "MYT2", 18, addrs, 1000 * 10 ** 18);
        appendedWhitelistTokensForUpgrade.push(address(appendedToken));

        /// deploy vault implementationcontract that has logics called by proxy
        vaultImplementation = new Vault();

        /// deploy the vault beacon that store the implementation contract address
        vaultBeacon = new UpgradeableBeacon(address(vaultImplementation));

        // deploy BeaconProxyBytecode to store BeaconProxyBytecode
        beaconProxyBytecode = new BeaconProxyBytecode();

        // then the ProxyAdmin
        proxyAdmin = new CustomProxyAdmin();
        // then the logic
        clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(clientChainId, exocoreValidatorSet);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        // then the params + proxy
        spawnTime = block.timestamp + 1 hours;
        offsetDuration = 30 minutes;
        bootstrap = Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                deployer,
                                spawnTime,
                                offsetDuration,
                                payable(exocoreValidatorSet),
                                whitelistTokens,
                                address(proxyAdmin)
                            )
                        )
                    )
                )
            )
        );
        // validate the initialization
        assertTrue(bootstrap.isWhitelistedToken(address(myToken)));
        assertFalse(bootstrap.isWhitelistedToken(address(0xa)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 1);
        assertFalse(bootstrap.bootstrapped());
        proxyAdmin.initialize(address(bootstrap));
        // deployer is the owner
        address expectedVaultAddress = Create2.computeAddress(
            bytes32(uint256(uint160(address(myToken)))),
            keccak256(abi.encodePacked(BEACON_PROXY_BYTECODE, abi.encode(address(vaultBeacon), ""))),
            address(bootstrap)
        );
        assertTrue(address(bootstrap.tokenToVault(address(myToken))) == expectedVaultAddress);
        // now set the gateway address for Exocore.
        clientChainLzEndpoint.setDestLzEndpoint(undeployedExocoreGateway, undeployedExocoreLzEndpoint);
        bootstrap.setPeer(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)));
        // lastly set up the upgrade params

        // deploy capsule implementation contract that has logics called by proxy
        capsuleImplementation = new ExoCapsule();

        // deploy the capsule beacon that store the implementation contract address
        capsuleBeacon = new UpgradeableBeacon(address(capsuleImplementation));

        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(0x1),
            address(vaultBeacon),
            address(capsuleBeacon),
            address(beaconProxyBytecode)
        );
        // uint256 tokenCount = bootstrap.getWhitelistedTokensCount();
        // address[] memory tokensForCall = new address[](tokenCount);
        // for (uint256 i = 0; i < tokenCount; i++) {
        //     tokensForCall[i] = bootstrap.whitelistTokens(i);
        // }
        bytes memory initialization = abi.encodeCall(
            clientGatewayLogic.initialize,
            (
                // bootstrap.exocoreChainId(),
                // bootstrap.exocoreValidatorSetAddress(),
                // tokensForCall
                payable(exocoreValidatorSet),
                appendedWhitelistTokensForUpgrade
            )
        );
        bootstrap.setClientChainGatewayLogic(address(clientGatewayLogic), initialization);
        vm.stopPrank();
    }

    function test01_AddWhitelistToken() public returns (MyToken) {
        vm.startPrank(deployer);
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        bootstrap.addWhitelistToken(address(myTokenClone));
        vm.stopPrank();
        assertTrue(bootstrap.isWhitelistedToken(address(myTokenClone)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 2);
        return myTokenClone;
    }

    function test01_AddWhitelistToken_AlreadyExists() public {
        vm.startPrank(deployer);
        vm.expectRevert("BootstrapStorage: token should be not whitelisted before");
        bootstrap.addWhitelistToken(address(myToken));
        vm.stopPrank();
    }

    function test02_Deposit() public {
        // Distribute MyToken to addresses
        vm.startPrank(deployer);
        for (uint256 i = 0; i < 6; i++) {
            // from constructor logic, some initial balance is present.
            uint256 prevBalance = myToken.balanceOf(addrs[i]);
            myToken.transfer(addrs[i], amounts[i]);
            uint256 newBalance = myToken.balanceOf(addrs[i]);
            assertTrue(newBalance == prevBalance + amounts[i]);
        }
        vm.stopPrank();

        // Make deposits and check values
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            Vault vault = Vault(address(bootstrap.tokenToVault(address(myToken))));
            myToken.approve(address(vault), amounts[i]);
            uint256 prevDepositorsCount = bootstrap.getDepositorsCount();
            bool prevIsDepositor = bootstrap.isDepositor(addrs[i]);
            uint256 prevBalance = myToken.balanceOf(addrs[i]);
            uint256 prevDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 prevWithdrawable = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            uint256 prevTokenDeposit = bootstrap.depositsByToken(address(myToken));
            bootstrap.deposit(address(myToken), amounts[i]);
            uint256 newBalance = myToken.balanceOf(addrs[i]);
            assertTrue(newBalance == prevBalance - amounts[i]);
            uint256 newDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            assertTrue(newDeposit == prevDeposit + amounts[i]);
            uint256 newWithdrawable = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            assertTrue(newWithdrawable == prevWithdrawable + amounts[i]);
            if (!prevIsDepositor) {
                assertTrue(bootstrap.isDepositor(addrs[i]));
                assertTrue(bootstrap.getDepositorsCount() == prevDepositorsCount + 1);
            } else {
                assertTrue(bootstrap.getDepositorsCount() == prevDepositorsCount);
            }
            assertTrue(bootstrap.depositsByToken(address(myToken)) == prevTokenDeposit + amounts[i]);
            vm.stopPrank();
        }
    }

    function test02_Deposit_WithoutApproval() public {
        // make a transfer
        vm.startPrank(deployer);
        myToken.transfer(addrs[0], amounts[0]);
        vm.stopPrank();
        assertTrue(myToken.balanceOf(addrs[0]) >= amounts[0]);

        // now try to deposit
        vm.startPrank(addrs[0]);
        vm.expectRevert();
        bootstrap.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_ZeroBalance() public {
        // Make deposits without having any balance
        vm.startPrank(addrs[0]);
        uint256 balance = myToken.balanceOf(addrs[0]);
        myToken.burn(balance);
        assertTrue(myToken.balanceOf(addrs[0]) == 0);
        myToken.approve(address(bootstrap), amounts[0]);
        vm.expectRevert();
        bootstrap.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_NonWhitelistedToken() public {
        address cloneDeployer = address(0xdebd);
        // Deploy a new token
        vm.startPrank(cloneDeployer);
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        address cloneAddress = address(myTokenClone);
        vm.stopPrank();

        // now transfer it to address[0]
        vm.startPrank(cloneDeployer);
        myTokenClone.transfer(addrs[0], amounts[0]);

        // now try to deposit
        myToken.approve(address(bootstrap), amounts[0]);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.deposit(cloneAddress, amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_Success() public {
        address cloneDeployer = address(0xdebd);
        // Deploy a new token
        vm.startPrank(cloneDeployer);
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        address cloneAddress = address(myTokenClone);
        vm.stopPrank();

        // now transfer it to address[0]
        vm.startPrank(cloneDeployer);
        myTokenClone.transfer(addrs[0], amounts[0]);
        vm.stopPrank();

        // now add it to the whitelist
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(cloneAddress);
        vm.stopPrank();

        // now try to deposit
        vm.startPrank(addrs[0]);
        IVault vault = bootstrap.tokenToVault(cloneAddress);
        myTokenClone.approve(address(vault), amounts[0]);
        bootstrap.deposit(cloneAddress, amounts[0]);
        vm.stopPrank();
    }

    function test03_RegisterOperator() public {
        assertTrue(bootstrap.getOperatorsCount() == 0);
        // Register operators. The keys used below do not matter since they are unit test only.
        string[3] memory operators = [
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac",
            "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2",
            "exo1rtg0cgw94ep744epyvanc0wdd5kedwql73vlmr"
        ];
        string[3] memory names = ["operator1", "operator2", "operator3"];
        bytes32[3] memory pubKeys = [
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782),
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9),
            bytes32(0xa29429a3ca352334fbe75df9485544bd517e3718df73725f33c6d06f3c1caade)
        ];
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            bootstrap.registerOperator(operators[i], names[i], commission, pubKeys[i]);
            // check count
            assertTrue(bootstrap.getOperatorsCount() == i + 1);
            // check ethToExocoreAddress mapping
            string memory exoAddress = bootstrap.ethToExocoreAddress(addrs[i]);
            assertTrue(keccak256(abi.encodePacked(exoAddress)) == keccak256(abi.encodePacked(operators[i])));
            (string memory name, IOperatorRegistry.Commission memory thisCommision, bytes32 key) = bootstrap.operators(
                exoAddress
            );
            assertTrue(keccak256(abi.encodePacked(name)) == keccak256(abi.encodePacked(names[i])));
            assertTrue(key == pubKeys[i]);
            assertTrue(thisCommision.rate == commission.rate);
            vm.stopPrank();
        }
    }

    function test03_RegisterOperator_EthAlreadyRegistered() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        // change all identifying params except eth address of operator
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        name = "operator1_re";
        pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Ethereum address already linked to an operator");
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.stopPrank();
    }

    function test03_RegisterOperator_ExoAlreadyRegistered() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        // change all identifying params except exo address of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        name = "operator1_re";
        pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Operator with this Exocore address is already registered");
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.stopPrank();
    }

    function test03_RegisterOperator_ConsensusKeyInUse() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);

        // change all identifying params except consensus key of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        name = "operator1_re";
        vm.expectRevert("Consensus public key already in use");
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.stopPrank();
    }

    function test03_RegisterOperator_NameInUse() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);

        // change all identifying params except name of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Name already in use");
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        assertTrue(bootstrap.getOperatorsCount() == 1);
        (, , bytes32 consensusPublicKey) = bootstrap.operators(exo);
        assertTrue(consensusPublicKey == pubKey);
        // Then change the key
        bytes32 newKey = bytes32(0xd995b7f4b2178b0466cfa512955ce2299a4487ebcd86f817d686880dd2b7c4b0);
        bootstrap.replaceKey(newKey);
        (, , consensusPublicKey) = bootstrap.operators(exo);
        assertTrue(consensusPublicKey == newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseByOther() public {
        test03_RegisterOperator();
        // Then change the key
        vm.startPrank(addrs[0]);
        bytes32 newKey = bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseBySelf() public {
        test03_RegisterOperator();
        // Then change the key for the same address
        vm.startPrank(addrs[1]);
        bytes32 newKey = bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_Unregistered() public {
        vm.startPrank(addrs[1]);
        bytes32 newKey = bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("no such operator exists");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test06_UpdateRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        bootstrap.updateRate(1e17);
        (, IOperatorRegistry.Commission memory newCommission, ) = bootstrap.operators(exo);
        assertTrue(newCommission.rate == 1e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_Twice() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        bootstrap.updateRate(1e17);
        (, IOperatorRegistry.Commission memory newCommission, ) = bootstrap.operators(exo);
        assertTrue(newCommission.rate == 1e17);
        vm.expectRevert("Commission already edited once");
        bootstrap.updateRate(1e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_MoreThanMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e17, 1e17);
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.expectRevert("Rate exceeds max rate");
        bootstrap.updateRate(2e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_MoreThanMaxChangeRate() public {
        // 0, 0.1, 0.01
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e17, 1e16);
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey = bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(exo, name, commission, pubKey);
        vm.expectRevert("Rate change exceeds max change rate");
        bootstrap.updateRate(2e16);
        vm.stopPrank();
    }

    function test06_UpdateRate_Unregistered() public {
        // Register one operator
        address addr = address(0x7);
        vm.startPrank(addr);
        vm.expectRevert("no such operator exists");
        bootstrap.updateRate(1e18);
        vm.stopPrank();
    }

    function test07_AddWhitelistedToken() public {
        // any address can deploy the token
        vm.startPrank(address(0x1));
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        address cloneAddress = address(myTokenClone);
        vm.stopPrank();
        // only the owner can add the token to the supported list
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(cloneAddress);
        vm.stopPrank();
        // finally, check
        bool isSupported = bootstrap.isWhitelistedToken(cloneAddress);
        assertTrue(isSupported);
    }

    function test07_AddWhitelistedToken_AlreadyWhitelisted() public {
        vm.startPrank(deployer);
        vm.expectRevert("BootstrapStorage: token should be not whitelisted before");
        bootstrap.addWhitelistToken(address(myToken));
        vm.stopPrank();
    }

    function test08_ExocoreAddressIsValid() public {
        assertTrue(bootstrap.isValidExocoreAddress("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac"));
    }

    function test08_ExocoreAddressIsValid_Length() public {
        assertFalse(bootstrap.isValidExocoreAddress("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7acaa"));
    }

    function test08_ExocoreAddressIsValid_Prefix() public {
        assertFalse(bootstrap.isValidExocoreAddress("asd"));
    }

    function test09_DelegateTo() public {
        // first, register the operators
        test03_RegisterOperator();
        // then, make the transfers and deposits
        test02_Deposit();
        // first, self delegate
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            string memory exo = bootstrap.ethToExocoreAddress(addrs[i]);
            uint256 prevDelegation = bootstrap.delegations(addrs[i], exo, address(myToken));
            uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
            uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            bootstrap.delegateTo(exo, address(myToken), amounts[i]);
            uint256 postDelegation = bootstrap.delegations(addrs[i], exo, address(myToken));
            uint256 postDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
            uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            assertTrue(postDelegation == prevDelegation + amounts[i]);
            assertTrue(postDelegationByOperator == prevDelegationByOperator + amounts[i]);
            assertTrue(postWithdrawableAmount == prevWithdrawableAmount - amounts[i]);
            vm.stopPrank();
        }
        // finally, delegate from stakers to the operators
        uint8[3][3] memory delegations = [[8, 9, 0], [0, 7, 8], [2, 0, 6]];
        for (uint256 i = 0; i < 3; i++) {
            address delegator = addrs[i + 3];
            vm.startPrank(delegator);
            for (uint256 j = 0; j < 3; j++) {
                uint256 amount = delegations[i][j] * 10 ** 18;
                if (amount != 0) {
                    string memory exo = bootstrap.ethToExocoreAddress(addrs[j]);
                    uint256 prevDelegation = bootstrap.delegations(delegator, exo, address(myToken));
                    uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
                    uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(delegator, address(myToken));
                    bootstrap.delegateTo(exo, address(myToken), uint256(amount));
                    uint256 postDelegation = bootstrap.delegations(delegator, exo, address(myToken));
                    uint256 postDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
                    uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(delegator, address(myToken));
                    assertTrue(postDelegation == prevDelegation + amount);
                    assertTrue(postDelegationByOperator == prevDelegationByOperator + amount);
                    assertTrue(postWithdrawableAmount == prevWithdrawableAmount - amount);
                }
            }
            vm.stopPrank();
        }
    }

    function test09_DelegateTo_Unregistered() public {
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Operator does not exist");
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]);
    }

    function test09_DelegateTo_TokenNotWhitelisted() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]);
    }

    function test09_DelegateTo_NotEnoughBlance() public {
        test03_RegisterOperator();
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(bytes("Bootstrap: insufficient withdrawable balance"));
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]);
    }

    function test09_DelegateTo_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: amount should be greater than zero");
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), 0);
    }

    function test09_DelegateTo_NoDeposits() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient withdrawable balance");
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]);
    }

    function test09_DelegateTo_Excess() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient withdrawable balance");
        bootstrap.delegateTo("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0] + 1);
    }

    function test10_UndelegateFrom() public {
        test09_DelegateTo();
        // first, self undelegate
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            string memory exo = bootstrap.ethToExocoreAddress(addrs[i]);
            uint256 prevDelegation = bootstrap.delegations(addrs[i], exo, address(myToken));
            uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
            uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            bootstrap.undelegateFrom(exo, address(myToken), amounts[i]);
            uint256 postDelegation = bootstrap.delegations(addrs[i], exo, address(myToken));
            uint256 postDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
            uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            assertTrue(postDelegation == prevDelegation - amounts[i]);
            assertTrue(postDelegationByOperator == prevDelegationByOperator - amounts[i]);
            assertTrue(postWithdrawableAmount == prevWithdrawableAmount + amounts[i]);
            vm.stopPrank();
        }
        // finally, undelegate from stakers to the operators
        uint8[3][3] memory delegations = [[8, 9, 0], [0, 7, 8], [2, 0, 6]];
        for (uint256 i = 0; i < 3; i++) {
            address delegator = addrs[i + 3];
            vm.startPrank(delegator);
            for (uint256 j = 0; j < 3; j++) {
                uint256 amount = delegations[i][j] * 10 ** 18;
                if (amount != 0) {
                    string memory exo = bootstrap.ethToExocoreAddress(addrs[j]);
                    uint256 prevDelegation = bootstrap.delegations(delegator, exo, address(myToken));
                    uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
                    uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(delegator, address(myToken));
                    bootstrap.undelegateFrom(exo, address(myToken), uint256(amount));
                    uint256 postDelegation = bootstrap.delegations(delegator, exo, address(myToken));
                    uint256 postDelegationByOperator = bootstrap.delegationsByOperator(exo, address(myToken));
                    uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(delegator, address(myToken));
                    assertTrue(postDelegation == prevDelegation - amount);
                    assertTrue(postDelegationByOperator == prevDelegationByOperator - amount);
                    assertTrue(postWithdrawableAmount == prevWithdrawableAmount + amount);
                }
            }
            vm.stopPrank();
        }
    }

    function test10_UndelegateFrom_Unregistered() public {
        test09_DelegateTo();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Operator does not exist");
        bootstrap.undelegateFrom("exo1awm72f4sc5yhedurdunx9afcshfq6ymqva8an4", address(myToken), amounts[0]);
    }

    function test10_UndelegateFrom_TokenNotWhitelisted() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.undelegateFrom("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]);
    }

    function test10_UndelegateFrom_NotEnoughBalance() public {
        test03_RegisterOperator();
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(bytes("Bootstrap: insufficient delegated balance"));
        bootstrap.undelegateFrom("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]);
    }

    function test10_UndelegateFrom_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: amount should be greater than zero");
        bootstrap.undelegateFrom("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), 0);
    }

    function test10_UndelegateFromOperator_Excess() public {
        test09_DelegateTo();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient delegated balance");
        bootstrap.undelegateFrom("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0] + 1);
    }

    function test10_UndelegateFrom_NoDelegation() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient delegated balance");
        bootstrap.undelegateFrom("exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]);
    }

    function test11_WithdrawPrincipleFromExocore() public {
        // delegate and then undelegate
        test10_UndelegateFrom();
        // now, withdraw
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            uint256 prevDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 prevWithdrawable = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            uint256 prevTokenDeposit = bootstrap.depositsByToken(address(myToken));
            uint256 prevVaultWithdrawable = Vault(address(bootstrap.tokenToVault(address(myToken))))
                .withdrawableBalances(addrs[i]);
            bootstrap.withdrawPrincipleFromExocore(address(myToken), amounts[i]);
            uint256 postDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 postWithdrawable = bootstrap.withdrawableAmounts(addrs[i], address(myToken));
            uint256 postTokenDeposit = bootstrap.depositsByToken(address(myToken));
            uint256 postVaultWithdrawable = Vault(address(bootstrap.tokenToVault(address(myToken))))
                .withdrawableBalances(addrs[i]);
            assertTrue(postDeposit == prevDeposit - amounts[i]);
            assertTrue(postWithdrawable == prevWithdrawable - amounts[i]);
            assertTrue(postTokenDeposit == prevTokenDeposit - amounts[i]);
            assertTrue(postVaultWithdrawable == prevVaultWithdrawable + amounts[i]);
            // check the vault too
            vm.stopPrank();
        }
    }

    function test11_WithdrawPrincipleFromExocore_TokenNotWhitelisted() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.withdrawPrincipleFromExocore(address(0xa), amounts[0]);
        vm.stopPrank();
    }

    function test11_WithdrawPrincipleFromExocore_ZeroAmount() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: amount should be greater than zero");
        bootstrap.withdrawPrincipleFromExocore(address(myToken), 0);
        vm.stopPrank();
    }

    function test11_WithdrawPrincipleFromExocore_NoDeposits() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient deposited balance");
        bootstrap.withdrawPrincipleFromExocore(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test11_WithdrawPrincipleFromExocore_Excess() public {
        test10_UndelegateFrom();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient deposited balance");
        bootstrap.withdrawPrincipleFromExocore(address(myToken), amounts[0] + 1);
        vm.stopPrank();
    }

    function test11_WithdrawPrincipleFromExocore_ExcessFree() public {
        test09_DelegateTo();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient withdrawable balance");
        bootstrap.withdrawPrincipleFromExocore(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test12_MarkBootstrapped() public {
        vm.warp(spawnTime + 1);
        vm.startPrank(address(0x20));
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)), uint64(1)),
            address(bootstrap),
            generateUID(1),
            abi.encodePacked(GatewayStorage.Action.MARK_BOOTSTRAP, ""),
            bytes("")
        );
        vm.stopPrank();
        assertTrue(bootstrap.bootstrapped());
        // ensure that it cannot be upgraded ever again.
        assertTrue(bootstrap.customProxyAdmin() == address(0));
        assertTrue(proxyAdmin.bootstrapper() == address(0));
        assertTrue(bootstrap.owner() == exocoreValidatorSet);
        // getDepositorsCount is no longer a function so can't check the count.
        // assertTrue(bootstrap.getDepositorsCount() == 0);
    }

    function test12_MarkBootstrapped_NotTime() public {
        vm.startPrank(address(0x20));
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)), uint64(1)),
            address(bootstrap),
            generateUID(1),
            abi.encodePacked(GatewayStorage.Action.MARK_BOOTSTRAP, ""),
            bytes("")
        );
        vm.stopPrank();
        assertFalse(bootstrap.bootstrapped());
    }

    function test12_MarkBootstrapped_AlreadyBootstrapped() public {
        test12_MarkBootstrapped();
        vm.startPrank(address(clientChainLzEndpoint));
        vm.expectRevert(
            abi.encodeWithSelector(GatewayStorage.UnsupportedRequest.selector, GatewayStorage.Action.MARK_BOOTSTRAP)
        );
        bootstrap.lzReceive(
            Origin(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)), uint64(2)),
            generateUID(1),
            abi.encodePacked(GatewayStorage.Action.MARK_BOOTSTRAP, ""),
            address(0),
            bytes("")
        );
        vm.stopPrank();
    }

    function test12_MarkBootstrapped_DirectCall() public {
        vm.startPrank(address(0x20));
        vm.warp(spawnTime + 2);
        vm.expectRevert("BootstrapLzReceiver: could only be called from this contract itself with low level call");
        bootstrap.markBootstrapped();
        vm.stopPrank();
    }

    function test13_OperationAllowed() public {
        vm.warp(spawnTime - offsetDuration);
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: operation not allowed after lock time");
        bootstrap.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test14_IsCommissionValid() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1e18);
        assertTrue(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(1.1e18, 1e18, 1e18);
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1.1e18, 1e18);
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0, 1e18, 1.1e18);
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateExceedsMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0.5e18, 0.2e18, 1e18);
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateExceedsMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(0.1e18, 0.2e18, 1e18);
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function generateUID(uint64 nonce) internal view returns (bytes32 uid) {
        uid = GUID.generate(
            nonce,
            exocoreChainId,
            address(undeployedExocoreGateway),
            clientChainId,
            bytes32(bytes20(address(bootstrap)))
        );
    }

    function test15_Initialize_OwnerZero() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: owner should not be empty");
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                address(0x0),
                                spawnTime,
                                offsetDuration,
                                payable(exocoreValidatorSet),
                                whitelistTokens,
                                address(proxyAdmin)
                            )
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_SpawnTimeNotFuture() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.warp(20);
        vm.expectRevert("Bootstrap: spawn time should be in the future");
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                deployer,
                                block.timestamp - 10,
                                offsetDuration,
                                payable(exocoreValidatorSet),
                                whitelistTokens,
                                address(proxyAdmin)
                            )
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_OffsetDurationZero() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: offset duration should be greater than 0");
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (deployer, spawnTime, 0, payable(exocoreValidatorSet), whitelistTokens, address(proxyAdmin))
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_SpawnTimeLTOffsetDuration() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: spawn time should be greater than offset duration");
        vm.warp(20);
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (deployer, 21, 22, payable(exocoreValidatorSet), whitelistTokens, address(proxyAdmin))
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_LockTimeNotFuture() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: lock time should be in the future");
        vm.warp(20);
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (deployer, 21, 9, payable(exocoreValidatorSet), whitelistTokens, address(proxyAdmin))
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_ExocoreValSetZero() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: exocore validator set address should not be empty");
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                deployer,
                                spawnTime,
                                offsetDuration,
                                payable(address(0)),
                                whitelistTokens,
                                address(proxyAdmin)
                            )
                        )
                    )
                )
            )
        );
    }

    function test15_Initialize_CustomProxyAdminZero() public {
        vm.startPrank(deployer);
        Bootstrap bootstrapLogic = new Bootstrap(
            address(clientChainLzEndpoint),
            exocoreChainId,
            address(vaultBeacon),
            address(beaconProxyBytecode)
        );
        vm.expectRevert("Bootstrap: custom proxy admin should not be empty");
        Bootstrap(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(bootstrapLogic),
                        address(proxyAdmin),
                        abi.encodeCall(
                            bootstrap.initialize,
                            (
                                deployer,
                                spawnTime,
                                offsetDuration,
                                payable(exocoreValidatorSet),
                                whitelistTokens,
                                address(0x0)
                            )
                        )
                    )
                )
            )
        );
    }

    function test16_SetSpawnTime() public {
        vm.startPrank(deployer);
        bootstrap.setSpawnTime(block.timestamp + 35 minutes);
        assertTrue(bootstrap.exocoreSpawnTime() == block.timestamp + 35 minutes);
    }

    function test16_SetSpawnTime_NotInFuture() public {
        vm.startPrank(deployer);
        vm.warp(10);
        vm.expectRevert("Bootstrap: spawn time should be in the future");
        bootstrap.setSpawnTime(9);
    }

    function test16_SetSpawnTime_LessThanOffsetDuration() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: spawn time should be greater than offset duration");
        bootstrap.setSpawnTime(offsetDuration - 1);
    }

    function test16_SetSpawnTime_LockTimeNotInFuture() public {
        vm.startPrank(deployer);
        vm.warp(offsetDuration - 1);
        console.log(block.timestamp, offsetDuration, spawnTime);
        vm.expectRevert("Bootstrap: lock time should be in the future");
        // the initial block.timestamp is 1, so subtract 2 here - 1 for
        // the test and 1 for the warp offset above.
        bootstrap.setSpawnTime(spawnTime - 2);
    }

    function test17_SetOffsetDuration() public {
        vm.startPrank(deployer);
        bootstrap.setOffsetDuration(offsetDuration + 1);
        assertTrue(bootstrap.offsetDuration() == offsetDuration + 1);
    }

    function test17_SetOffsetDuration_GTESpawnTime() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: spawn time should be greater than offset duration");
        bootstrap.setOffsetDuration(spawnTime);
    }

    function test17_SetOffsetDuration_LockTimeNotInFuture() public {
        vm.warp(offsetDuration - 1);
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: lock time should be in the future");
        bootstrap.setOffsetDuration(offsetDuration + 2);
    }

    function test18_RemoveWhitelistToken() public {
        vm.startPrank(deployer);
        bootstrap.removeWhitelistToken(address(myToken));
        assertFalse(bootstrap.isWhitelistedToken(address(myToken)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 0);
    }

    function test18_RemoveWhitelistToken_DoesNotExist() public {
        address fakeToken = address(0xa);
        vm.startPrank(deployer);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.removeWhitelistToken(fakeToken);
    }

    function test20_WithdrawRewardFromExocore() public {
        vm.expectRevert(abi.encodeWithSignature("NotYetSupported()"));
        bootstrap.withdrawRewardFromExocore(address(0x0), 1);
    }

    function test22_Claim() public {
        test11_WithdrawPrincipleFromExocore();
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            uint256 prevBalance = myToken.balanceOf(addrs[i]);
            bootstrap.claim(address(myToken), amounts[i], addrs[i]);
            uint256 postBalance = myToken.balanceOf(addrs[i]);
            assertTrue(postBalance == prevBalance + amounts[i]);
            vm.stopPrank();
        }
    }

    function test22_Claim_TokenNotWhitelisted() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: token is not whitelisted");
        bootstrap.claim(address(0xa), amounts[0], addrs[0]);
    }

    function test22_Claim_ZeroAmount() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("BootstrapStorage: amount should be greater than zero");
        bootstrap.claim(address(myToken), 0, addrs[0]);
    }

    function test22_Claim_Excess() public {
        test11_WithdrawPrincipleFromExocore();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Vault: withdrawal amount is larger than depositor's withdrawable balance");
        bootstrap.claim(address(myToken), amounts[0] + 5, addrs[0]);
    }
}
