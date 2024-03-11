pragma solidity ^0.8.19;

import "../src/core/ClientChainGateway.sol";
import {Vault} from "../src/core/Vault.sol";
import "../src/core/ExocoreGateway.sol";
import "@openzeppelin-contracts/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@layerzero-v2/protocol/contracts/interfaces/ILayerZeroEndpointV2.sol";

contract BaseScriptStorage {
    struct Player {
        uint256 privateKey;
        address addr;
    }

    Player deployer;
    Player exocoreValidatorSet;
    Player exocoreGenesis;
    Player depositor;
    Player relayer;

    string clientChainRPCURL;
    string exocoreRPCURL;

    address[] whitelistTokens;
    address[] vaults;

    ClientChainGateway clientGateway;
    Vault vault;
    ExocoreGateway exocoreGateway;
    ILayerZeroEndpointV2 clientChainLzEndpoint;
    ILayerZeroEndpointV2 exocoreLzEndpoint;
    ERC20PresetFixedSupply restakeToken;

    uint256 clientChain;
    uint256 exocore;

    uint16 constant exocoreChainId = 40259;
    uint16 constant clientChainId = 40161;

    address constant sepoliaEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address constant exocoreEndpointV2 = 0x6EDCE65403992e310A62460808c4b910D972f10f;
    address constant erc20TokenAddress = 0x83E6850591425e3C1E263c054f4466838B9Bd9e4;

    uint256 constant DEPOSIT_AMOUNT = 1e22;
}
