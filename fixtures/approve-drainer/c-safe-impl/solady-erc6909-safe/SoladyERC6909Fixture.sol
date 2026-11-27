// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC6909} from "../../../vendor/solady/ERC6909.sol";

/// @title SoladyERC6909Fixture - concrete multi-token over the UNMODIFIED Solady ERC6909.
/// @notice Tier-(c) real-safe HOLDOUT vehicle for approve-drainer. The per-id allowance
///         accounting under test is Solady's unmodified EIP-6909 (fixtures/vendor/solady/
///         ERC6909.sol, MIT, Vectorized/solady v0.1.22, commit
///         65e87c72a5ee4a6708946b25611ec5f980ceba70; byte-identical, self-contained). This
///         subclass adds ONLY the required metadata overrides + a test-only mint; it changes none
///         of the defensive logic. EIP-6909 is a DIFFERENT allowance model (per-token-id
///         allowances + operator flag) from the ERC-20 fixtures, so a clean verdict is a genuine
///         precision signal on an unseen safe surface. Built/run only in Docker.
contract SoladyERC6909Fixture is ERC6909 {
    function name(uint256) public pure override returns (string memory) {
        return "Solady Safe Multitoken (holdout)";
    }

    function symbol(uint256) public pure override returns (string memory) {
        return "SSM";
    }

    function tokenURI(uint256) public pure override returns (string memory) {
        return "";
    }

    /// @dev Test-only mint of `amount` of token `id` to `to`.
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount);
    }
}
