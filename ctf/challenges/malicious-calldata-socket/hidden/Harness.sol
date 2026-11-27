// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Socket call-injection gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.

/// @dev Minimal ERC-20 with the approval surface the vector needs. A victim grants the gateway
///      a standing allowance; the injected transferFrom spends it because the gateway is msg.sender.
contract MockERC20 {
    string public name = "Mock";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "ERC20: insufficient allowance");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev The one audited route implementation the gateway is allowed to call. Its `settle` is a
///      legitimate routed action (the "feature"); it moves no native ETH.
contract TrustedRoute {
    uint256 public settlements;

    function settle() external {
        settlements += 1;
    }
}
