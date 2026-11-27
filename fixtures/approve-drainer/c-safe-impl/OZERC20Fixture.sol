// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the approve-drainer vector.
// The safety-relevant logic - allowance accounting and `transferFrom`'s
// `_spendAllowance` check - is the UNMODIFIED OpenZeppelin ERC20:
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures vendor/oz/LICENSE)
// This file adds ONLY a test-only, unguarded `mint` entrypoint and a
// constructor so a fixture can fund a wallet in one call. It changes none
// of OZ's authorization logic. Never deploy this on a real network.
// ====================================================================

import {ERC20} from "../../vendor/oz/token/ERC20/ERC20.sol";

/// @title OZERC20Fixture - a concrete, genuinely-OpenZeppelin ERC-20.
/// @notice Real OZ v5.1.0 ERC20 semantics: an unlimited allowance
///         (type(uint256).max) is NOT decremented on transferFrom, while any
///         bounded allowance IS decremented and caps what a spender can pull.
///         That real behaviour is what makes a bounded-approve flow safe.
contract OZERC20Fixture is ERC20 {
    constructor() ERC20("OZ Fixture Token", "OZFT") {}

    /// @notice Test-only mint (no access control on purpose; fixtures only).
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
