pragma solidity =0.8.12;

import "lib/eigenlayer-middleware/src/libraries/BN254.sol";

contract BN254Caller {
    using BN254 for BN254.G1Point;

    bytes public aggregatedPubkeys;
    bytes public aggregatedSigs;
    bytes32 public expectedMsg = keccak256(bytes("this is a test message"));
    bool public verifyValid;
    bool public aggregateVerifyValid;

    uint256 internal constant PAIRING_EQUALITY_CHECK_GAS = 120000;

    function aggregatePubkeysPure(BN254.G1Point[] calldata pubkeys) external view returns(BN254.G1Point memory apk) {
        apk = BN254.G1Point(0,0);
        for (uint8 i; i < pubkeys.length; i++) {
            apk = apk.plus(pubkeys[i]);
        }
    }

    function fastAggregateVerifyPure(
        bytes32 msgHash,
        BN254.G1Point[] calldata pubkeys,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) 
        external 
        view 
        returns(bool) 
    {
        BN254.G1Point memory apk = BN254.G1Point(0,0);
        for (uint8 i; i < pubkeys.length; i++) {
            apk = apk.plus(pubkeys[i]);
        }

        (bool pairingSuccessful, bool signatureIsValid) = trySignatureAndApkVerification(
            msgHash, 
            apk, 
            apkG2, 
            sigma
        );
        require(pairingSuccessful, "BLSSignatureChecker.checkSignatures: pairing precompile call failed");
        require(signatureIsValid, "BLSSignatureChecker.checkSignatures: signature is invalid");
        return signatureIsValid;
    }

    function trySignatureAndApkVerification(
        bytes32 msgHash,
        BN254.G1Point memory apk,
        BN254.G2Point memory apkG2,
        BN254.G1Point memory sigma
    ) public view returns(bool pairingSuccessful, bool siganatureIsValid) {
        // gamma = keccak256(abi.encodePacked(msgHash, apk, apkG2, sigma))
        uint256 gamma = uint256(keccak256(abi.encodePacked(msgHash, apk.X, apk.Y, apkG2.X[0], apkG2.X[1], apkG2.Y[0], apkG2.Y[1], sigma.X, sigma.Y))) % BN254.FR_MODULUS;
        // verify the signature
        (pairingSuccessful, siganatureIsValid) = BN254.safePairing(
                sigma.plus(apk.scalar_mul(gamma)),
                BN254.negGeneratorG2(),
                BN254.hashToG1(msgHash).plus(BN254.generatorG1().scalar_mul(gamma)),
                apkG2,
                120000
            );
    }
}