// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the address-poisoning gate. Kept out of the player's work
// copy until `solve` runs. Minimal toy - never deploy it.

/// @dev Minimal ERC-20. The wallet (Challenge) holds the balance and pays out with transfer.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
