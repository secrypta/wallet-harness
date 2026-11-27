// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the approve-drainer vector.
// The safety-relevant logic - the ERC-4626 vault share token's allowance
// accounting and `transferFrom` `_spendAllowance` check - is the UNMODIFIED
// OpenZeppelin ERC4626 (which is an ERC20):
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures vendor/oz/LICENSE)
// This file adds ONLY a concrete constructor (naming the share token + its
// underlying asset) and a test-only `mintShares` entrypoint. It changes none
// of OZ's authorization logic. Never deploy this on a real network.
// ====================================================================

import {IERC20} from "../../vendor/oz/token/ERC20/IERC20.sol";
import {ERC20} from "../../vendor/oz/token/ERC20/ERC20.sol";
import {ERC4626} from "../../vendor/oz/token/ERC20/extensions/ERC4626.sol";

/// @title OZERC4626Fixture - a concrete, genuinely-OpenZeppelin ERC-4626 vault.
/// @notice A tokenized vault whose SHARE token is a real OZ ERC20. A bounded approve on
///         the shares is decremented by OZ's own `_spendAllowance`, so a spender can never
///         move more shares than were granted - the approve-drainer full-balance pull on
///         vault shares reverts. Exercises the detector's silence on a real vault token,
///         a distinct real contract surface from a plain ERC20.
contract OZERC4626Fixture is ERC4626 {
    constructor(IERC20 asset_) ERC20("OZ Vault Share", "OZVS") ERC4626(asset_) {}

    /// @notice Test-only share mint (no access control on purpose; fixtures only).
    function mintShares(address to, uint256 shares) external {
        _mint(to, shares);
    }
}
