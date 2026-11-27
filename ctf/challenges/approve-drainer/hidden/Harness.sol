// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the approve-drainer gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.

/// @dev Minimal ERC-20 with just the surface the vector needs.
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
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev A spender the wallet authorizes. Used both as the legitimate puller (pulls the
///      agreed amount) and as the attacker (tries to pull the full balance).
contract Spender {
    function pull(address token, address wallet, uint256 amount) external {
        MockERC20(token).transferFrom(wallet, address(this), amount);
    }
}
