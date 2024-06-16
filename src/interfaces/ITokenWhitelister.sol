pragma solidity ^0.8.19;

interface ITokenWhitelister {

    function addWhitelistTokens(address[] calldata tokens) external payable;
    function getWhitelistedTokensCount() external returns (uint256);
}
