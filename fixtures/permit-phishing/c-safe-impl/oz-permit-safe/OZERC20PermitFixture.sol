// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the permit-phishing vector.
// The safety-relevant logic - EIP-2612 `permit` signature verification, nonce handling,
// deadline enforcement and allowance accounting - is the UNMODIFIED OpenZeppelin
// ERC20Permit (+ EIP712 / ECDSA / Nonces):
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures vendor/oz/LICENSE)
// This file adds ONLY a test-only, unguarded `mint` entrypoint and the constructor that
// names the EIP-712 domain. It changes none of OZ's permit logic. Never deploy this on a
// real network.
// ====================================================================

import {ERC20} from "../../../vendor/oz/token/ERC20/ERC20.sol";
import {ERC20Permit} from "../../../vendor/oz/token/ERC20/extensions/ERC20Permit.sol";

/// @title OZERC20PermitFixture - a concrete, genuinely-OpenZeppelin EIP-2612 token.
/// @notice Real OZ v5.1.0 `permit`: a signature authorizes an allowance of EXACTLY the
///         signed `value`. A bounded permit (value = action amount) therefore caps a
///         spender to that amount; a later full-balance `transferFrom` reverts on the OZ
///         allowance check. That real behaviour is what makes the bounded-permit flow safe.
contract OZERC20PermitFixture is ERC20, ERC20Permit {
    constructor() ERC20("OZ Permit Token", "OZPT") ERC20Permit("OZ Permit Token") {}

    /// @notice Test-only mint (no access control on purpose; fixtures only).
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
