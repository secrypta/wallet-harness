// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the Lixir forged-permit gate. Kept out of the player's work
// copy until `solve` runs. Minimal toy - never deploy it.

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @dev A spender that pulls tokens via transferFrom once it holds an allowance. Used both as
///      the attacker (after a forged permit) and as the legitimate spender (after a genuine one).
contract Spender {
    function pull(address token, address owner, uint256 amount) external {
        IToken(token).transferFrom(owner, address(this), amount);
    }
}
