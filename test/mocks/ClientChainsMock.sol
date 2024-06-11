pragma solidity ^0.8.19;

import {IClientChains} from "../../src/interfaces/precompiles/IClientChains.sol";

contract ClientChainsMock is IClientChains {

    uint16 clientChainId = 40_161;

    function getClientChains() external view returns (bool, uint16[] memory) {
        uint16[] memory res = new uint16[](1);
        res[0] = clientChainId;
        return (true, res);
    }

}
