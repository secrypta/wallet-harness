// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the create2-metamorphic gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.

interface IChallenge {
    function pull(address to, uint256 amount) external;
}

/// @dev Minimal ERC-20 with just the surface the vector needs.
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

/// @dev The VETTED trustee: the benign code the wallet authorizes. It pulls a scoped amount
///      to a given recipient - a legitimate helper (the "feature").
contract BenignTrustee {
    function withdraw(address wallet, address to, uint256 amount) external {
        IChallenge(wallet).pull(to, amount);
    }
}

/// @dev The HOSTILE code that an attacker swaps in at the already-trusted address (the swap
///      is modelled with `vm.etch` in the gate - a toy/offline stand-in for a metamorphic or
///      look-alike redeploy). Running at the trusted address, it pulls the full balance to
///      the attacker.
contract HostileTrustee {
    function drain(address wallet, address token, address attacker) external {
        uint256 bal = MockERC20(token).balanceOf(wallet);
        IChallenge(wallet).pull(attacker, bal);
    }
}
