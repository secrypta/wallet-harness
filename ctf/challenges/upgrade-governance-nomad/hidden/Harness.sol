// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the Nomad re-init gate. Kept out of the player's work copy
// until `solve` runs, so the exploit stays hidden.

/// @dev Minimal ERC-20 standing in for the custodied bridged asset (WBTC in the incident).
contract MockERC20 {
    string public name = "Mock";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
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
