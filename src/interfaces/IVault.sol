pragma solidity ^0.8.19;

interface IVault {
    function withdrawalRequest(address token, address recipient, uint256 amount) external payable;

    function depositRequest(address token, address sender, uint256 amount) external;
}