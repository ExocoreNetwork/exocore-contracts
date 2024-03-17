pragma solidity ^0.8.19;

contract GatewayStorage {
    enum Action {
      REQUEST_DEPOSIT,
      REQUEST_WITHDRAW_PRINCIPLE_FROM_EXOCORE,
      REQUEST_DELEGATE_TO,
      REQUEST_UNDELEGATE_FROM,
      RESPOND,
      UPDATE_USERS_BALANCES
    }

    mapping(Action => bytes4) public whiteListFunctionSelectors;
    address payable public ExocoreValidatorSetAddress;

    uint256[40] private __gap;
}