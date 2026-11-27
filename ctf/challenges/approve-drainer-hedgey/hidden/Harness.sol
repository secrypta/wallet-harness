// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Hedgey stale-approval gate. Kept out of the player's work
// copy until `solve` runs. Minimal toys - never deploy them.

/// @dev Minimal USDC-like ERC-20 (6 decimals) - the pooled asset the stale approval drained.
contract UsdcLikeToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
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

/// @dev The attacker's "locker": the address the attacker passes to createLockedCampaign. After
///      cancel leaves its approval standing, it transferFroms the contract's pooled balance.
contract AttackerLocker {
    function drain(address token, address claimContract, address to, uint256 amount) external {
        UsdcLikeToken(token).transferFrom(claimContract, to, amount);
    }
}
