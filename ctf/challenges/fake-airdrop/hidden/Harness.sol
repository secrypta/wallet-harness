// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the fake-airdrop gate. No imports from the corpus /
// fixtures / vendor - the CTF is decoupled from the harness core by code.

/// @dev Minimal ERC-20 with just the surface the vector needs.
contract MockERC20 {
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

/// @dev The "claim helper" the wallet authorizes. The legit use pulls the worthless gift
///      token; the attack reuses the same authorization to pull the real, valuable asset.
contract ClaimHelper {
    function pull(address token, address wallet, uint256 amount) external {
        MockERC20(token).transferFrom(wallet, address(this), amount);
    }
}
