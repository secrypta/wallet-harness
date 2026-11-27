// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Pennysia arbitrary-route gate. Kept out of the player's
// work copy until `solve` runs. Minimal toys - never deploy them.

/// @dev Minimal USDC-like ERC-20 (6 decimals). Victims grant the Settlement a standing approval.
contract MiniUSDC {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        require(balanceOf[from] >= amt, "insufficient");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amt;
        }
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @dev A legitimate swap venue. Holds its own reserve and pays out an amount when routed to -
///      a real routed action that does NOT touch any user's approval.
contract MockDex {
    MiniUSDC public immutable token;

    constructor(address _token) {
        token = MiniUSDC(_token);
    }

    function payout(address to, uint256 amt) external {
        token.transfer(to, amt);
    }
}
