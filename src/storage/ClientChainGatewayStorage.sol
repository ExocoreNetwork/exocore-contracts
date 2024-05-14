pragma solidity ^0.8.19;

import {BootstrapStorage} from "./BootstrapStorage.sol";
import {IVault} from "../interfaces/IVault.sol";
import {IExoCapsule} from "../interfaces/IExoCapsule.sol";
import {IETHPOSDeposit} from "../interfaces/IETHPOSDeposit.sol";
import {BootstrapStorage} from "../storage/BootstrapStorage.sol";

import {IBeacon} from "@openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol";

contract ClientChainGatewayStorage is BootstrapStorage {
    /* -------------------------------------------------------------------------- */
    /*       state variables exclusively owned by ClientChainGateway              */
    /* -------------------------------------------------------------------------- */

    uint64 public outboundNonce;
    mapping(address => IExoCapsule) public ownerToCapsule;
    mapping(uint64 => bytes) _registeredRequests;
    mapping(uint64 => Action) _registeredRequestActions;
    mapping(Action => bytes4) _registeredResponseHooks;

    // immutable state variables
    address public immutable beaconOracleAddress;
    IBeacon public immutable exoCapsuleBeacon;

    // constant state variables
    bytes constant EXO_ADDRESS_PREFIX = bytes("exo1");
    uint128 constant DESTINATION_GAS_LIMIT = 500000;
    uint128 constant DESTINATION_MSG_VALUE = 0;
    uint256 constant GWEI_TO_WEI = 1e9;
    address constant VIRTUAL_STAKED_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    IETHPOSDeposit constant ETH_POS = IETHPOSDeposit(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    uint256[40] private __gap;

    /* -------------------------------------------------------------------------- */
    /*     ClientChainGateway Events(besides inherited from BootstrapStorage)     */
    /* -------------------------------------------------------------------------- */

    /* ----------------- whitelist tokens and vaults management ----------------- */
    event WhitelistTokenAdded(address _token);
    event WhitelistTokenRemoved(address _token);
    event VaultCreated(address _underlyingToken, address _vault);

    /* ---------------------------- native restaking ---------------------------- */
    event CapsuleCreated(address owner, address capsule);
    event StakedWithCapsule(address staker, address capsule);

    /* ----------------------------- restaking      ----------------------------- */
    event ClaimSucceeded(address token, address recipient, uint256 amount);
    event WithdrawRewardResult(bool indexed success, address indexed token, address indexed withdrawer, uint256 amount);

    /* -------------------------------------------------------------------------- */
    /*                                   Errors                                   */
    /* -------------------------------------------------------------------------- */

    error CapsuleNotExist();

    modifier isTokenWhitelisted(address token) {
        require(isWhitelistedToken[token], "BaseRestakingController: token is not whitelisted");
        _;
    }

    modifier isValidAmount(uint256 amount) {
        require(amount > 0, "BaseRestakingController: amount should be greater than zero");
        _;
    }

    modifier vaultExists(address token) {
        require(address(tokenToVault[token]) != address(0), "BaseRestakingController: no vault added for this token");
        _;
    }

    modifier isValidBech32Address(string calldata exocoreAddress) {
        require(
            _isValidExocoreAddress(exocoreAddress),
            "BaseRestakingController: invalid bech32 encoded Exocore address"
        );
        _;
    }

    constructor(
        uint32 exocoreChainId_,
        address beaconOracleAddress_,
        address vaultBeacon_,
        address exoCapsuleBeacon_
    ) BootstrapStorage(exocoreChainId_, vaultBeacon_) {
        require(
            beaconOracleAddress_ != address(0),
            "ClientChainGatewayStorage: beacon chain oracle address should not be empty"
        );
        require(
            exoCapsuleBeacon_ != address(0),
            "ClientChainGatewayStorage: the exoCapsuleBeacon address for beacon proxy should not be empty"
        );

        beaconOracleAddress = beaconOracleAddress_;
        exoCapsuleBeacon = IBeacon(exoCapsuleBeacon_);
    }

    function _isValidExocoreAddress(string calldata operatorExocoreAddress) public pure returns (bool) {
        bytes memory stringBytes = bytes(operatorExocoreAddress);
        if (stringBytes.length != 42) {
            return false;
        }
        for (uint i = 0; i < EXO_ADDRESS_PREFIX.length; i++) {
            if (stringBytes[i] != EXO_ADDRESS_PREFIX[i]) {
                return false;
            }
        }

        return true;
    }

    function _getCapsule(address owner) internal view returns (IExoCapsule) {
        IExoCapsule capsule = ownerToCapsule[owner];
        if (address(capsule) == address(0)) {
            revert CapsuleNotExist();
        }
        return capsule;
    }
}
