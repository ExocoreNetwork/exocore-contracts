pragma solidity ^0.8.19;

interface IVault {
    event WithdrawProtocolRevenue(
        address recipient,
        address token,
        uint256 amount
    );

    function withdrawalRequest(
        address token,
        address recipient,
        uint256 amount
    ) external payable;

    function depositRequest(
        address token,
        address sender,
        uint256 amount
    ) external;
}