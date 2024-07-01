pragma solidity ^0.8.19;

/// @title Events Library
/// @notice A library for all events used throughout the protocol

library Events {

    /////////////////////
    //  Common Events  //
    /////////////////////
    event DelegateVotesChanged(address indexed delegate, uint256 previousVotes, uint256 newVotes);

}
