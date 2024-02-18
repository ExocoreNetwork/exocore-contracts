pragma solidity =0.8.12;

import "forge-std/Script.sol";
import "lib/eigenlayer-middleware/src/libraries/BN254.sol";
import "../src/mocks/BN254Caller.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract BN254Script is Script {    
    using BN254 for BN254.G1Point;

    struct Player {
        uint256 privateKey;
        address addr;
    }

    bytes32 msgHash = keccak256(abi.encodePacked("hello world"));
    uint256 aggSignerPrivKey = 69;

    BN254.G2Point aggSignerApkG2;
    BN254.G1Point sigma;

    Player exocoreDeployer;
    string exocoreRPCURL;
    uint256 exocore;

    Player clientChainDeployer;

    function setUp() public {
        // aggSignerPrivKey*g2
        aggSignerApkG2.X[1] = 19101821850089705274637533855249918363070101489527618151493230256975900223847;
        aggSignerApkG2.X[0] = 5334410886741819556325359147377682006012228123419628681352847439302316235957;
        aggSignerApkG2.Y[1] = 354176189041917478648604979334478067325821134838555150300539079146482658331;
        aggSignerApkG2.Y[0] = 4185483097059047421902184823581361466320657066600218863748375739772335928910;

        sigma = BN254.hashToG1(msgHash).scalar_mul(aggSignerPrivKey);

        exocoreDeployer.privateKey = vm.envUint("TEST_ACCOUNT_ONE_PRIVATE_KEY");
        exocoreDeployer.addr = vm.addr(exocoreDeployer.privateKey);
        exocoreRPCURL = vm.envString("EXOCORE_TESETNET_RPC");
        exocore = vm.createSelectFork(exocoreRPCURL);

        // clientChainDeployer.privateKey = vm.envUint("ANVIL_DEPLOYER_PRIVATE_KEY");
        // clientChainDeployer.addr = vm.addr(clientChainDeployer.privateKey);
        // vm.startBroadcast(clientChainDeployer.privateKey);
        // if (exocoreDeployer.addr.balance < 1 ether) {
        //     payable(exocoreDeployer.addr).transfer(1 ether);
        // }
        // vm.stopBroadcast();
    }

    function generatePrivateKeys() internal view returns (uint256[] memory) {
        uint256[] memory signerPrivateKeys = new uint256[](100);
        // generate numSigners numbers that add up to aggSignerPrivKey mod BN254.FR_MODULUS
        uint256 sum = 0;
        for (uint i = 0; i < 99; i++) {
            signerPrivateKeys[i] = uint256(keccak256(abi.encodePacked("signerPrivateKey", i))) % BN254.FR_MODULUS;
            sum = addmod(sum, signerPrivateKeys[i], BN254.FR_MODULUS);
        }
        // signer private keys need to add to aggSignerPrivKey
        signerPrivateKeys[99] = addmod(aggSignerPrivKey, BN254.FR_MODULUS - sum % BN254.FR_MODULUS, BN254.FR_MODULUS);

        return signerPrivateKeys;
    }

    function generatePublicKeys(uint256[] memory _privateKeys) internal returns (BN254.G1Point[] memory) {
        BN254.G1Point[] memory _pubkeys = new BN254.G1Point[](_privateKeys.length);
        for (uint i; i < _privateKeys.length; i++) {
            _pubkeys[i] = BN254.generatorG1().scalar_mul(_privateKeys[i]);
        }
        return _pubkeys;
    }

    function run() public {
        uint256[] memory privateKeys;
        BN254.G1Point[] memory pubkeys;
        privateKeys = generatePrivateKeys();
        pubkeys = generatePublicKeys(privateKeys);

        string memory finalJson;
        string memory pubkeysJson = "pubkeys";
        string memory pubkeysJsonOutput;
        for (uint i; i < pubkeys.length; i++) {
            uint256[] memory xy = new uint256[](2);
            xy[0] = pubkeys[i].X;
            xy[1] = pubkeys[i].Y;
            pubkeysJsonOutput = vm.serializeUint(pubkeysJson, Strings.toString(i), xy);
        }
        vm.serializeString(finalJson, "pubkeys", pubkeysJsonOutput);

        vm.serializeBytes32(finalJson, "msg", msgHash);

        uint256[] memory sig = new uint256[](2);
        sig[0] = sigma.X;
        sig[1] = sigma.Y;
        vm.serializeUint(finalJson, "sigma", sig);

        uint256[] memory xy2 = new uint256[](4);
        xy2[0] = aggSignerApkG2.X[0];
        xy2[1] = aggSignerApkG2.X[1];
        xy2[2] = aggSignerApkG2.Y[0];
        xy2[3] = aggSignerApkG2.Y[1];
        string memory finalJsonOutput = vm.serializeUint(finalJson, "apkG2", xy2);

        vm.writeJson(finalJsonOutput, "script/bn254Pubkeys.json");
        BN254.G1Point[] memory sli = new BN254.G1Point[](2);
        sli[0] = pubkeys[0];
        sli[1] = pubkeys[1];
        bytes memory data = abi.encodeWithSelector(
            BN254Caller.fastAggregateVerifyPure.selector,
            msgHash,
            pubkeys,
            aggSignerApkG2,
            sigma
        );
        console.log(data.length);
        console.logBytes(data);
        // console.log("pubkey1:", pubkeys[0].X, pubkeys[0].Y);
        // console.log("pubkey2:", pubkeys[1].X, pubkeys[1].Y);

        vm.selectFork(exocore);
        vm.startBroadcast(exocoreDeployer.privateKey);

        // BN254Caller bn254Caller = new BN254Caller();
        // console.log("caller contract address:", address(bn254Caller));
        // BN254.G1Point memory apk = bn254Caller.aggregatePubkeysPure(pubkeys);
        // bool valid = bn254Caller.fastAggregateVerifyPure(
        //     msgHash,
        //     pubkeys,
        //     aggSignerApkG2,
        //     sigma
        // );
        // (bool success, bytes memory ret) = address(bn254Caller).call(data);
        // console.log("success:", success);
        // console.log("aggregated pubkey:", apk.X, apk.Y);
        // console.log("verification valid:", valid);
    }
}