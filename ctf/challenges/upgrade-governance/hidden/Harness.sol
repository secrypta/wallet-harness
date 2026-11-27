// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the upgrade-governance gate. Kept out of the player's
// work copy until `solve` runs, so the exploit stays hidden.
//
// The logic contracts are delegatecalled by the wallet, so they run in the wallet's storage
// context. They declare NO storage of their own (only an external token call), so they do
// not collide with the wallet's `implementation` / `pendingImpl` / `pendingEta` slots.

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

/// @dev The legitimate implementation: `run` pays the wallet's fixed withdrawal address
///      (`PAYEE`) the requested amount. A compromised key calling this cannot redirect funds.
contract BenignLogic {
    address internal constant PAYEE = address(0xBEEF);

    function run(address token, uint256 amount) external {
        MockERC20(token).transfer(PAYEE, amount);
    }
}

/// @dev The hostile implementation an attacker wants to swap in: `run` ignores its arguments
///      and sweeps the wallet's full balance to the attacker.
contract HostileLogic {
    address internal constant DRAIN_TO = address(0xA77ACC);

    function run(address token, uint256) external {
        MockERC20 t = MockERC20(token);
        t.transfer(DRAIN_TO, t.balanceOf(address(this)));
    }
}
