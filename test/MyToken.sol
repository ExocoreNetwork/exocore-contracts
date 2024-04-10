// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

contract MyToken is ERC20Burnable {
    uint8 private _decimals;

    constructor(
        string memory name, string memory symbol, uint8 customDecimals,
        address[] memory initialAddresses, uint256 initialBalance
    ) ERC20(name, symbol) {
        _mint(msg.sender, initialBalance * 100);
        for(uint256 i = 0; i < initialAddresses.length; i++) {
            _mint(initialAddresses[i], initialBalance);
        }
        _decimals = customDecimals;
    }

    // We override this here so that we can test multiple types of decimals.
    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }
}
