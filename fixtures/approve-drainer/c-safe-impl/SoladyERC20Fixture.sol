// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../../vendor/solady/ERC20.sol";

/// @title SoladyTokenFixture - concrete token over the UNMODIFIED vendored Solady ERC20.
/// @notice Real-safe HOLDOUT vehicle. The safety-relevant logic under test - ERC-20 allowance
///         accounting and the EIP-2612 `permit` signature check - is Solady's unmodified
///         `ERC20` (fixtures/vendor/solady/ERC20.sol, MIT, pinned commit; see
///         fixtures/vendor/PROVENANCE.md). This subclass adds ONLY the two abstract metadata
///         getters and a test-only `mint`; it changes none of the defensive logic.
///
///         Solady is an independent implementation (not OpenZeppelin, not Permit2) that the wal
///         detectors were NOT tuned against - so fixtures built on it are a genuine `holdout`
///         precision test: the harness must stay silent (BLOCKED) on this unseen safe code.
contract SoladyTokenFixture is ERC20 {
    function name() public pure override returns (string memory) {
        return "Solady Safe Token (holdout)";
    }

    function symbol() public pure override returns (string memory) {
        return "SST";
    }

    /// @dev Test-only mint to fund a holder for the offline safe-behavior check.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
