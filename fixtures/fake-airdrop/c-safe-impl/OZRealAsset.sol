// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the fake-airdrop vector.
// The safety-relevant logic - allowance accounting and transferFrom's
// _spendAllowance check - is the UNMODIFIED OpenZeppelin ERC20:
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures/vendor/oz/LICENSE)
// This file adds ONLY a test-only `mint` and a constructor; it reuses the
// already-vendored OZ ERC20 (nothing in vendor/ is modified) and changes none
// of OZ's authorization logic. Never deploy this on a real network.
// ====================================================================

import {ERC20} from "../../vendor/oz/token/ERC20/ERC20.sol";

/// @title OZRealAsset - a concrete, genuinely-OpenZeppelin ERC-20 used as the victim's REAL
///        asset in the fake-airdrop (c) safe flow.
/// @notice Real OZ v5.1.0 semantics: a bounded allowance IS decremented and caps what a
///         spender can pull, so a claim that grants no drainable allowance on the real
///         asset leaves a full-balance drain reverting on unmodified OZ `_spendAllowance`.
contract OZRealAsset is ERC20 {
    constructor() ERC20("OZ Real Asset", "OZRA") {}

    /// @notice Test-only mint (no access control on purpose; fixtures only).
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
