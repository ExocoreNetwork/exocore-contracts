pragma solidity ^0.8.19;

interface ITokenWhitelister {
    function addWhitelistToken(address _token) external;
    function removeWhitelistToken(address _token) external;
    function addTokenVaults(address[] calldata vaults) external;
}