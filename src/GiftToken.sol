// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title GiftToken - the worthless "gift" bait of the fake-airdrop vector.
/// @notice Toy token for test scenarios only. The constructor mints the whole supply to a
///         `recipient` that never asked for it, mirroring an unsolicited airdrop landing
///         in a victim's wallet. The gift itself is never the target: it only lures the
///         victim into a "claim" flow that grants an allowance on their REAL asset.
///         An unsolicited token balance is itself the entry-point flag of the scam.
contract GiftToken {
    string public name = "Free Gift (unsolicited) - test only";
    string public symbol = "GIFT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// @param recipient address the unsolicited "gift" is dropped on (the victim).
    constructor(address recipient) {
        _mint(recipient, 5000e18);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "GIFT: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "GIFT: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
