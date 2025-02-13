// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {INativeRestakingController} from "../interfaces/INativeRestakingController.sol";
import {ILSTRestakingController} from "./ILSTRestakingController.sol";

import {IOAppCore} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/interfaces/IOAppCore.sol";
import {IOAppReceiver} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/interfaces/IOAppReceiver.sol";

interface IClientChainGateway is IOAppReceiver, IOAppCore, ILSTRestakingController, INativeRestakingController {

    /// @notice Calculates the native fee for sending a message with specific options.
    /// @param _message The message for which the fee is being calculated.
    /// @return nativeFee The calculated native fee for the given message.
    function quote(bytes memory _message) external view returns (uint256 nativeFee);

}
