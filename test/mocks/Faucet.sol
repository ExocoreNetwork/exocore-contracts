pragma solidity ^0.8.19;

contract Faucet {
    mapping(uint => uint) gasSentWithinBlock;
    mapping(address => uint) receivedLastBlock;
    event GasSent(address receiver, uint amount);
    // Accept any incoming amount
    receive() external payable {}

    // Give out ether to anyone who asks
    function request(uint amount) public {
        // Limit withdrawal amount
        require(amount <= 1 ether);
        require(block.number >= receivedLastBlock[msg.sender]+1, "you have received gas in this block");
        gasSentWithinBlock[block.number] += 1 ether; 
        if (gasSentWithinBlock[block.number] > 10 ether) {
            revert("gas airdrop finished in this block");
        }
        // Send the amount to the address that requested it
        (bool success, ) = msg.sender.call{value: amount}("");
        if (success) {
            emit GasSent(msg.sender, amount); 
        }
    }
}