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
import {ClientChainGatewayStorage} from "../../src/storage/ClientChainGatewayStorage.sol";
import {IController} from "../../src/interfaces/IController.sol";

contract BootstrapTest is Test {
    MyToken myToken;
    Bootstrap bootstrap;
    address[] addrs = new address[](6);
    uint256[] amounts = [
        35 * 10 ** 18,  // self
        25 * 10 ** 18,  // self
        10 * 10 ** 18,  // self
        17 * 10 ** 18,  // 8 + 9 + 0
        15 * 10 ** 18,  // 0 + 7 + 8
        8 * 10 ** 18    // 2 + 0 + 6
    ];
    address deployer = address(0xdeadbeef);
    uint256 spawnTime;
    uint256 offsetTime;
    uint16 exocoreChainId = 1;
    uint16 clientChainId = 2;
    address[] whitelistTokens;
    address[] vaults;
    NonShortCircuitEndpointV2Mock clientChainLzEndpoint;
    address exocoreValidatorSet = vm.addr(uint256(0x8));
    address undeployedExocoreGateway = vm.addr(uint256(0x9));
    address undeployedExocoreLzEndpoint = vm.addr(uint256(0xb));

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
        // then the ProxyAdmin
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        // then the logic
        clientChainLzEndpoint = new NonShortCircuitEndpointV2Mock(
            clientChainId, exocoreValidatorSet
        );
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        // then the params + proxy
        spawnTime = block.timestamp + 1 hours;
        offsetTime = 30 minutes;
        bootstrap = Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, spawnTime, offsetTime, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
        // validate the initialization
        assertTrue(bootstrap.whitelistTokens(address(myToken)));
        assertFalse(bootstrap.whitelistTokens(address(0xa)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 1);
        assertFalse(bootstrap.bootstrapped());
        assertTrue(bootstrap.whiteListFunctionSelectors(GatewayStorage.Action.MARK_BOOTSTRAP) != bytes4(0));
        // any one case
        assertTrue(bootstrap.whiteListFunctionSelectors(GatewayStorage.Action.REQUEST_DEPOSIT) == bytes4(0));
        proxyAdmin.setBootstrapper(address(bootstrap));
        // deployer is the owner
        Vault vaultLogic = new Vault();
        Vault vault = Vault(address(new TransparentUpgradeableProxy(
            address(vaultLogic), address(proxyAdmin), ""
        )));
        vault.initialize(address(myToken), address(bootstrap));
        vaults.push(address(vault));
        bootstrap.addTokenVaults(vaults);
        assertTrue(address(bootstrap.tokenVaults(address(myToken))) == address(vault));
        // now set the gateway address for Exocore.
        clientChainLzEndpoint.setDestLzEndpoint(
            undeployedExocoreGateway, undeployedExocoreLzEndpoint
        );
        bootstrap.setPeer(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)));
        // lastly set up the upgrade params
        ClientChainGateway clientGatewayLogic = new ClientChainGateway(
            address(clientChainLzEndpoint)
        );
        // uint256 tokenCount = bootstrap.getWhitelistedTokensCount();
        // address[] memory tokensForCall = new address[](tokenCount);
        // for (uint256 i = 0; i < tokenCount; i++) {
        //     tokensForCall[i] = bootstrap.whitelistTokensArray(i);
        // }
        bytes memory initialization = abi.encodeCall(
            clientGatewayLogic.initialize,
            (
                // bootstrap.exocoreChainId(),
                // bootstrap.exocoreValidatorSetAddress(),
                // tokensForCall
                exocoreChainId,
                payable(exocoreValidatorSet),
                whitelistTokens
            )
        );
        bootstrap.setClientChainGatewayLogic(
            address(clientGatewayLogic),
            initialization
        );
        vm.stopPrank();
    }

    function test01_AddWhitelistToken() public returns (MyToken) {
        vm.startPrank(deployer);
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        bootstrap.addWhitelistToken(address(myTokenClone));
        vm.stopPrank();
        assertTrue(bootstrap.whitelistTokens(address(myTokenClone)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 2);
        return myTokenClone;
    }

    function test01_AddWhitelistToken_AlreadyExists() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: token should be not whitelisted before");
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
            myToken.approve(vaults[0], amounts[i]);
            uint256 prevDepositorsCount = bootstrap.getDepositorsCount();
            bool prevIsDepositor = bootstrap.isDepositor(addrs[i]);
            uint256 prevBalance = myToken.balanceOf(addrs[i]);
            uint256 prevDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 prevWithdrawable = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
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
            assertTrue(bootstrap.depositsByToken(address(myToken)) ==
                prevTokenDeposit + amounts[i]);
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
        vm.stopPrank();

        // now try to deposit
        myToken.approve(address(bootstrap), amounts[0]);
        vm.expectRevert("Bootstrap: token is not whitelisted");
        bootstrap.deposit(cloneAddress, amounts[0]);
        vm.stopPrank();
    }

    function test02_Deposit_VaultNotExist() public {
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

        // now try to deposit
        myToken.approve(address(bootstrap), amounts[0]);
        vm.expectRevert(abi.encodeWithSignature("VaultNotExist()"));
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
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            bootstrap.registerOperator(
                operators[i], names[i], commission, pubKeys[i]
            );
            // check count
            assertTrue(bootstrap.getOperatorsCount() == i + 1);
            // check ethToExocoreAddress mapping
            string memory exoAddress = bootstrap.ethToExocoreAddress(addrs[i]);
            assertTrue(
                keccak256(abi.encodePacked(exoAddress)) ==
                keccak256(abi.encodePacked(operators[i]))
            );
            (
                string memory name,
                IOperatorRegistry.Commission memory thisCommision,
                bytes32 key
            ) = bootstrap.operators(exoAddress);
            assertTrue(
                keccak256(abi.encodePacked(name)) ==
                keccak256(abi.encodePacked(names[i]))
            );
            assertTrue(key == pubKeys[i]);
            assertTrue(thisCommision.rate == commission.rate);
            vm.stopPrank();
        }
    }

    function test03_RegisterOperator_EthAlreadyRegistered() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        // change all identifying params except eth address of operator
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        name = "operator1_re";
        pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Ethereum address already linked to an operator");
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_ExoAlreadyRegistered() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        // change all identifying params except exo address of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        name = "operator1_re";
        pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Operator with this Exocore address is already registered");
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_ConsensusKeyInUse() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );

        // change all identifying params except consensus key of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        name = "operator1_re";
        vm.expectRevert("Consensus public key already in use");
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        vm.stopPrank();
    }

    function test03_RegisterOperator_NameInUse() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );

        // change all identifying params except name of operator
        vm.stopPrank();
        vm.startPrank(addrs[1]);
        exo = "exo1wnw7zcl9fy04ax69uffumwkdxftfqsjyj37wt2";
        pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540783);
        vm.expectRevert("Name already in use");
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        vm.stopPrank();
    }

    function test05_ReplaceKey() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        assertTrue(bootstrap.getOperatorsCount() == 1);
        (, , bytes32 consensusPublicKey ) = bootstrap.operators(exo);
        assertTrue(consensusPublicKey == pubKey);
        // Then change the key
        bytes32 newKey =
            bytes32(0xd995b7f4b2178b0466cfa512955ce2299a4487ebcd86f817d686880dd2b7c4b0);
        bootstrap.replaceKey(newKey);
        (, , consensusPublicKey ) = bootstrap.operators(exo);
        assertTrue(consensusPublicKey == newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseByOther() public {
        test03_RegisterOperator();
        // Then change the key
        vm.startPrank(addrs[0]);
        bytes32 newKey =
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_InUseBySelf() public {
        test03_RegisterOperator();
        // Then change the key for the same address
        vm.startPrank(addrs[1]);
        bytes32 newKey =
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("Consensus public key already in use");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test05_ReplaceKey_Unregistered() public {
        vm.startPrank(addrs[1]);
        bytes32 newKey =
            bytes32(0xe2f00b6510e16fd8cc5802a4011d6f093acbbbca7c284cad6aa2c2e474bb50f9);
        vm.expectRevert("no such operator exists");
        bootstrap.replaceKey(newKey);
        vm.stopPrank();
    }

    function test06_UpdateRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        bootstrap.updateRate(1e17);
        (, IOperatorRegistry.Commission memory newCommission, ) = bootstrap.operators(exo);
        assertTrue(newCommission.rate == 1e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_Twice() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        bootstrap.updateRate(1e17);
        (, IOperatorRegistry.Commission memory newCommission, ) = bootstrap.operators(exo);
        assertTrue(newCommission.rate == 1e17);
        vm.expectRevert("Commission already edited once");
        bootstrap.updateRate(1e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_MoreThanMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e17, 1e17
        );
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
        vm.expectRevert("Rate exceeds max rate");
        bootstrap.updateRate(2e17);
        vm.stopPrank();
    }

    function test06_UpdateRate_MoreThanMaxChangeRate() public {
        // 0, 0.1, 0.01
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e17, 1e16
        );
        // Register one operator
        string memory exo = "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac";
        string memory name = "operator1";
        bytes32 pubKey =
            bytes32(0x27165ec2f29a4815b7c29e47d8700845b5ae267f2d61ad29fb3939aec5540782);
        vm.startPrank(addrs[0]);
        bootstrap.registerOperator(
            exo, name, commission, pubKey
        );
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
        bool isSupported = bootstrap.whitelistTokens(cloneAddress);
        assertTrue(isSupported);
    }

    function test07_AddWhitelistedToken_AlreadyWhitelisted() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: token should be not whitelisted before");
        bootstrap.addWhitelistToken(address(myToken));
        vm.stopPrank();
    }

    // can add test08 next.

    function test09_DelegateTo() public {
        // first, register the operators
        test03_RegisterOperator();
        // then, make the transfers and deposits
        test02_Deposit();
        // first, self delegate
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            string memory exo = bootstrap.ethToExocoreAddress(addrs[i]);
            uint256 prevDelegation = bootstrap.delegations(
                addrs[i], exo, address(myToken)
            );
            uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(
                exo, address(myToken)
            );
            uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            bootstrap.delegateTo(
                exo, address(myToken), amounts[i]
            );
            uint256 postDelegation = bootstrap.delegations(
                addrs[i], exo, address(myToken)
            );
            uint256 postDelegationByOperator = bootstrap.delegationsByOperator(
                exo, address(myToken)
            );
            uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            assertTrue(postDelegation == prevDelegation + amounts[i]);
            assertTrue(postDelegationByOperator == prevDelegationByOperator + amounts[i]);
            assertTrue(postWithdrawableAmount == prevWithdrawableAmount - amounts[i]);
            vm.stopPrank();
        }
        // finally, delegate from stakers to the operators
        uint8[3][3] memory delegations = [
            [8, 9, 0],
            [0, 7, 8],
            [2, 0, 6]
        ];
        for (uint256 i = 0; i < 3; i++) {
            address delegator = addrs[i + 3];
            vm.startPrank(delegator);
            for(uint256 j = 0; j < 3; j++) {
                uint256 amount = delegations[i][j] * 10 ** 18;
                if (amount != 0) {
                    string memory exo = bootstrap.ethToExocoreAddress(addrs[j]);
                    uint256 prevDelegation = bootstrap.delegations(
                        delegator, exo, address(myToken)
                    );
                    uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(
                        exo, address(myToken)
                    );
                    uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(
                        delegator, address(myToken)
                    );
                    bootstrap.delegateTo(
                        exo, address(myToken), uint256(amount)
                    );
                    uint256 postDelegation = bootstrap.delegations(
                        delegator, exo, address(myToken)
                    );
                    uint256 postDelegationByOperator = bootstrap.delegationsByOperator(
                        exo, address(myToken)
                    );
                    uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(
                        delegator, address(myToken)
                    );
                    assertTrue(postDelegation == prevDelegation + amount);
                    assertTrue(
                        postDelegationByOperator == prevDelegationByOperator + amount
                    );
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
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]
        );
    }

    function test09_DelegateTo_TokenNotWhitelisted() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: token is not whitelisted");
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]
        );
    }

    function test09_DelegateTo_VaultNotExist() public {
        test03_RegisterOperator();
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(abi.encodeWithSignature("VaultNotExist()"));
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]
        );
    }

    function test09_DelegateTo_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: amount should be greater than zero");
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), 0
        );
    }

    function test09_DelegateTo_NoDeposits() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient withdrawable balance");
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]
        );
    }

    function test09_DelegateTo_Excess() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient withdrawable balance");
        bootstrap.delegateTo(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0] + 1
        );
    }

    function test10_UndelegateFrom() public {
        test09_DelegateTo();
        // first, self undelegate
        for (uint256 i = 0; i < 3; i++) {
            vm.startPrank(addrs[i]);
            string memory exo = bootstrap.ethToExocoreAddress(addrs[i]);
            uint256 prevDelegation = bootstrap.delegations(
                addrs[i], exo, address(myToken)
            );
            uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(
                exo, address(myToken)
            );
            uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            bootstrap.undelegateFrom(
                exo, address(myToken), amounts[i]
            );
            uint256 postDelegation = bootstrap.delegations(
                addrs[i], exo, address(myToken)
            );
            uint256 postDelegationByOperator = bootstrap.delegationsByOperator(
                exo, address(myToken)
            );
            uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            assertTrue(postDelegation == prevDelegation - amounts[i]);
            assertTrue(postDelegationByOperator == prevDelegationByOperator - amounts[i]);
            assertTrue(postWithdrawableAmount == prevWithdrawableAmount + amounts[i]);
            vm.stopPrank();
        }
        // finally, undelegate from stakers to the operators
        uint8[3][3] memory delegations = [
            [8, 9, 0],
            [0, 7, 8],
            [2, 0, 6]
        ];
        for (uint256 i = 0; i < 3; i++) {
            address delegator = addrs[i + 3];
            vm.startPrank(delegator);
            for(uint256 j = 0; j < 3; j++) {
                uint256 amount = delegations[i][j] * 10 ** 18;
                if (amount != 0) {
                    string memory exo = bootstrap.ethToExocoreAddress(addrs[j]);
                    uint256 prevDelegation = bootstrap.delegations(
                        delegator, exo, address(myToken)
                    );
                    uint256 prevDelegationByOperator = bootstrap.delegationsByOperator(
                        exo, address(myToken)
                    );
                    uint256 prevWithdrawableAmount = bootstrap.withdrawableAmounts(
                        delegator, address(myToken)
                    );
                    bootstrap.undelegateFrom(
                        exo, address(myToken), uint256(amount)
                    );
                    uint256 postDelegation = bootstrap.delegations(
                        delegator, exo, address(myToken)
                    );
                    uint256 postDelegationByOperator = bootstrap.delegationsByOperator(
                        exo, address(myToken)
                    );
                    uint256 postWithdrawableAmount = bootstrap.withdrawableAmounts(
                        delegator, address(myToken)
                    );
                    assertTrue(postDelegation == prevDelegation - amount);
                    assertTrue(
                        postDelegationByOperator == prevDelegationByOperator - amount
                    );
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
        bootstrap.undelegateFrom(
            "exo1awm72f4sc5yhedurdunx9afcshfq6ymqva8an4", address(myToken), amounts[0]
        );
    }

    function test10_UndelegateFrom_TokenNotWhitelisted() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: token is not whitelisted");
        bootstrap.undelegateFrom(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]
        );
    }

    function test10_UndelegateFrom_VaultNotExist() public {
        test03_RegisterOperator();
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(abi.encodeWithSignature("VaultNotExist()"));
        bootstrap.undelegateFrom(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(0xa), amounts[0]
        );
    }

    function test10_UndelegateFrom_ZeroAmount() public {
        test03_RegisterOperator();
        test02_Deposit();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: amount should be greater than zero");
        bootstrap.undelegateFrom(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), 0
        );
    }

    function test10_UndelegateFromOperator_Excess() public {
        test09_DelegateTo();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient delegated balance");
        bootstrap.undelegateFrom(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0] + 1
        );
    }

    function test10_UndelegateFrom_NoDelegation() public {
        test03_RegisterOperator();
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: insufficient delegated balance");
        bootstrap.undelegateFrom(
            "exo13hasr43vvq8v44xpzh0l6yuym4kca98f87j7ac", address(myToken), amounts[0]
        );
    }

    function test11_WithdrawPrincipleFromExocore() public {
        // delegate and then undelegate
        test10_UndelegateFrom();
        // now, withdraw
        for (uint256 i = 0; i < 6; i++) {
            vm.startPrank(addrs[i]);
            uint256 prevDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 prevWithdrawable = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            uint256 prevTokenDeposit = bootstrap.depositsByToken(address(myToken));
            uint256 prevVaultWithdrawable = Vault(
                address(bootstrap.tokenVaults(address(myToken)))
            ).withdrawableBalances(addrs[i]);
            bootstrap.withdrawPrincipleFromExocore(address(myToken), amounts[i]);
            uint256 postDeposit = bootstrap.totalDepositAmounts(addrs[i], address(myToken));
            uint256 postWithdrawable = bootstrap.withdrawableAmounts(
                addrs[i], address(myToken)
            );
            uint256 postTokenDeposit = bootstrap.depositsByToken(address(myToken));
            uint256 postVaultWithdrawable = Vault(
                address(bootstrap.tokenVaults(address(myToken)))
            ).withdrawableBalances(addrs[i]);
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
        vm.expectRevert("Bootstrap: token is not whitelisted");
        bootstrap.withdrawPrincipleFromExocore(address(0xa), amounts[0]);
        vm.stopPrank();
    }

    function test11_WithdrawPrincipleFromExocore_ZeroAmount() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: amount should be greater than zero");
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

    function test11_WithdrawPrincipleFromExocore_VaultNotExist() public {
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(abi.encodeWithSignature("VaultNotExist()"));
        bootstrap.withdrawPrincipleFromExocore(address(0xa), 5);
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
        vm.startPrank(address(0x20));
        vm.expectEmit(address(bootstrap));
        emit ClientChainGatewayStorage.UnsupportedRequestEvent(
            GatewayStorage.Action.MARK_BOOTSTRAP
        );
        clientChainLzEndpoint.lzReceive(
            Origin(exocoreChainId, bytes32(bytes20(undeployedExocoreGateway)), uint64(2)),
            address(bootstrap),
            generateUID(1),
            abi.encodePacked(GatewayStorage.Action.MARK_BOOTSTRAP, ""),
            bytes("")
        );
        vm.stopPrank();
    }

    function test12_MarkBootstrapped_DirectCall() public {
        vm.warp(spawnTime + 2);
        vm.expectRevert("ClientChainLzReceiver: could only be called from this contract itself with low level call");
        bootstrap.markBootstrapped();
        vm.stopPrank();
    }

    function test13_OperationAllowed() public {
        vm.warp(spawnTime - offsetTime);
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: operation not allowed after lock time");
        bootstrap.deposit(address(myToken), amounts[0]);
        vm.stopPrank();
    }

    function test14_IsCommissionValid() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1e18
        );
        assertTrue(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            1.1e18, 1e18, 1e18
        );
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1.1e18, 1e18
        );
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateLarge() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0, 1e18, 1.1e18
        );
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidRateExceedsMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0.5e18, 0.2e18, 1e18
        );
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function test14_IsCommissionValidMaxChangeRateExceedsMaxRate() public {
        IOperatorRegistry.Commission memory commission = IOperatorRegistry.Commission(
            0.1e18, 0.2e18, 1e18
        );
        assertFalse(bootstrap.isCommissionValid(commission));
    }

    function generateUID(
        uint64 nonce
    ) internal view returns (bytes32 uid) {
        uid = GUID.generate(
            nonce, exocoreChainId,
            address(undeployedExocoreGateway),
            clientChainId, bytes32(bytes20(address(bootstrap)))
        );
    }

    function test15_Initialize_OwnerZero() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: owner should not be empty");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (address(0x0), spawnTime, offsetTime, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_SpawnTimeNotFuture() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.warp(20);
        vm.expectRevert("Bootstrap: spawn time should be in the future");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, block.timestamp - 10, offsetTime, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_OffsetTimeZero() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: offset time should be greater than 0");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, spawnTime, 0, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_SpawnTimeLTOffsetTime() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: spawn time should be greater than offset time");
        vm.warp(20);
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, 21, 22, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_LockTimeNotFuture() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: lock time should be in the future");
        vm.warp(20);
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, 21, 9, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_ExocoreChainIdZero() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: exocore chain id should not be empty");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, spawnTime, offsetTime, 0,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_ExocoreValSetZero() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: exocore validator set address should not be empty");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, spawnTime, offsetTime, exocoreChainId,
                        payable(address(0)), whitelistTokens,
                        address(proxyAdmin))
                    )
                )
            ))
        );
    }

    function test15_Initialize_CustomProxyAdminZero() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Bootstrap bootstrapLogic = new Bootstrap(address(clientChainLzEndpoint));
        vm.expectRevert("Bootstrap: custom proxy admin should not be empty");
        Bootstrap(
            payable(address(
                new TransparentUpgradeableProxy(
                    address(bootstrapLogic), address(proxyAdmin),
                    abi.encodeCall(bootstrap.initialize,
                        (deployer, spawnTime, offsetTime, exocoreChainId,
                        payable(exocoreValidatorSet), whitelistTokens,
                        address(0x0))
                    )
                )
            ))
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

    function test16_SetSpawnTime_LessThanOffsetTime() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: spawn time should be greater than offset time");
        bootstrap.setSpawnTime(offsetTime - 1);
    }

    function test16_SetSpawnTime_LockTimeNotInFuture() public {
        vm.startPrank(deployer);
        vm.warp(offsetTime - 1);
        console.log(block.timestamp, offsetTime, spawnTime);
        vm.expectRevert("Bootstrap: lock time should be in the future");
        // the initial block.timestamp is 1, so subtract 2 here - 1 for
        // the test and 1 for the warp offset above.
        bootstrap.setSpawnTime(spawnTime - 2);
    }

    function test17_SetOffsetTime() public {
        vm.startPrank(deployer);
        bootstrap.setOffsetTime(offsetTime + 1);
        assertTrue(bootstrap.offsetTime() == offsetTime + 1);
    }

    function test17_SetOffsetTime_GTESpawnTime() public {
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: spawn time should be greater than offset time");
        bootstrap.setOffsetTime(spawnTime);
    }

    function test17_SetOffsetTime_LockTimeNotInFuture() public {
        vm.warp(offsetTime - 1);
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: lock time should be in the future");
        bootstrap.setOffsetTime(offsetTime + 2);
    }

    function test18_RemoveWhitelistToken() public {
        vm.startPrank(deployer);
        bootstrap.removeWhitelistToken(address(myToken));
        assertFalse(bootstrap.whitelistTokens(address(myToken)));
        assertTrue(bootstrap.getWhitelistedTokensCount() == 0);
    }

    function test18_RemoveWhitelistToken_DoesNotExist() public {
        address fakeToken = address(0xa);
        vm.startPrank(deployer);
        vm.expectRevert("Bootstrap: token should be already whitelisted");
        bootstrap.removeWhitelistToken(fakeToken);
    }

    function test19_AddTokenVaults() public {
        MyToken myTokenClone = test01_AddWhitelistToken();
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Vault vaultLogic = new Vault();
        Vault vault = Vault(address(new TransparentUpgradeableProxy(
            address(vaultLogic), address(proxyAdmin), ""
        )));
        vault.initialize(address(myTokenClone), address(bootstrap));
        address[] memory localVaults = new address[](1);
        localVaults[0] = address(vault);
        vm.startPrank(deployer);
        bootstrap.addTokenVaults(localVaults);
        assertTrue(address(bootstrap.tokenVaults(address(myTokenClone))) == address(vault));
    }

    function test19_AddTokenVaults_UnauthorizedToken() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        MyToken myTokenClone = new MyToken("MyToken", "MYT", 18, addrs, 1000 * 10 ** 18);
        Vault vaultLogic = new Vault();
        Vault vault = Vault(address(new TransparentUpgradeableProxy(
            address(vaultLogic), address(proxyAdmin), ""
        )));
        vault.initialize(address(myTokenClone), address(bootstrap));
        address[] memory localVaults = new address[](1);
        localVaults[0] = address(vault);
        vm.expectRevert(abi.encodeWithSignature("UnauthorizedToken()"));
        bootstrap.addTokenVaults(localVaults);
    }

    function test19_AddTokenVaults_VaultAlreadyAdded() public {
        vm.startPrank(deployer);
        CustomProxyAdmin proxyAdmin = new CustomProxyAdmin();
        Vault vaultLogic = new Vault();
        Vault vault = Vault(address(new TransparentUpgradeableProxy(
            address(vaultLogic), address(proxyAdmin), ""
        )));
        vault.initialize(address(myToken), address(bootstrap));
        address[] memory localVaults = new address[](1);
        localVaults[0] = address(vault);
        vm.expectRevert(abi.encodeWithSignature("VaultAlreadyAdded()"));
        bootstrap.addTokenVaults(localVaults);
    }

    function test20_WithdrawRewardFromExocore() public {
        vm.expectRevert(abi.encodeWithSignature("NotYetSupported()"));
        bootstrap.withdrawRewardFromExocore(address(0x0), 1);
    }

    function test21_UpdateUsersBalances() public {
        vm.expectRevert(abi.encodeWithSignature("NotYetSupported()"));
        IController.UserBalanceUpdateInfo[] memory x =
            new IController.UserBalanceUpdateInfo[](1);
        bootstrap.updateUsersBalances(x);
    }

    function test22_Claim() public {
        test11_WithdrawPrincipleFromExocore();
        for(uint256 i = 0; i < 6; i++) {
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
        vm.expectRevert("Bootstrap: token is not whitelisted");
        bootstrap.claim(address(0xa), amounts[0], addrs[0]);
    }

    function test22_Claim_ZeroAmount() public {
        vm.startPrank(addrs[0]);
        vm.expectRevert("Bootstrap: amount should be greater than zero");
        bootstrap.claim(address(myToken), 0, addrs[0]);
    }

    function test22_Claim_Excess() public {
        test11_WithdrawPrincipleFromExocore();
        vm.startPrank(addrs[0]);
        vm.expectRevert(
            "Vault: withdrawal amount is larger than depositor's withdrawable balance"
        );
        bootstrap.claim(address(myToken), amounts[0] + 5, addrs[0]);
    }

    function test22_Claim_VaultNotExist() public {
        vm.startPrank(deployer);
        bootstrap.addWhitelistToken(address(0xa));
        vm.stopPrank();
        vm.startPrank(addrs[0]);
        vm.expectRevert(abi.encodeWithSignature("VaultNotExist()"));
        bootstrap.claim(address(0xa), 5, addrs[0]);
    }
}
