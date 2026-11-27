// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the eip7702-delegation gate. No imports from the corpus /
// fixtures / vendor - the CTF is decoupled from the harness core by code.

/// @dev Minimal ERC-20 with just the surface the vector needs. The account holds the balance;
///      `batch` drives it to call `transfer` on this token.
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
