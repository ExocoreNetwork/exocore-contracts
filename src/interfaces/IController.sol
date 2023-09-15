pragma solidity ^0.8.19;

interface IController {
    event DepositResult(address indexed depositor, bool indexed success, uint256 amount);
    event WithdrawResult(address indexed withdrawer, bool indexed success, uint256 amount);
    event DelegateResult(address indexed delegator, address indexed delegatee, bool indexed success, uint256 amount);

    function deposit(address token, uint256 amount) external payable;
    function delegateTo(address operator, address token, uint256 amount) external;
    function withdraw(address token, uint256 amount, address distination) external;
    
}
