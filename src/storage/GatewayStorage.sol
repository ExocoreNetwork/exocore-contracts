pragma solidity ^0.8.19;

contract GatewayStorage {
    enum Action {
		REQUEST_DEPOSIT,
		REPLY_DEPOSIT,
		REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
    REPLY_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
		REQUEST_DELEGATE_TO,
    REPLY_DELEGATE_TO,
		REQUEST_UNDELEGATE_FROM,
    REPLY_UNDELEGATE_FROM,
		UPDATE_USERS_BALANCES
    }
    
    mapping(Action => bytes4) public whiteListFunctionSelectors;
    address payable public ExocoreValidatorSetAddress;
    
    uint256[40] private __gap;
}