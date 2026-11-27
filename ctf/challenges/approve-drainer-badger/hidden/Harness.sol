// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Badger approve-drainer gate. Kept out of the player's work
// copy until `solve` runs. Minimal toys - never deploy them.

/// @dev Minimal OpenZeppelin-style vault ERC-20 (byvWBTC-like, 8 decimals) with the
///      `increaseAllowance` surface the Badger front-end abused.
contract MockBadgerToken {
    string public name = "Badger Sett byvWBTC (toy)";
    string public symbol = "byvWBTC";
    uint8 public constant decimals = 8;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
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

/// @dev A spender the wallet authorizes. Legitimate puller (agreed amount) and attacker (full).
contract Spender {
    function pull(address token, address wallet, uint256 amount) external {
        MockBadgerToken(token).transferFrom(wallet, address(this), amount);
    }
}
