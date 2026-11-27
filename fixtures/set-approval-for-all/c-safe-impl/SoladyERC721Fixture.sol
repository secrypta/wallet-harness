// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "../../vendor/solady/ERC721.sol";

/// @title SoladyNFTFixture - concrete NFT over the UNMODIFIED vendored Solady ERC721.
/// @notice Real-safe HOLDOUT vehicle for the set-approval-for-all vector. The operator /
///         per-token authorization that stops a sweep of non-approved tokens is Solady's
///         unmodified `ERC721` (fixtures/vendor/solady/ERC721.sol, MIT, pinned commit; see
///         fixtures/vendor/PROVENANCE.md). This subclass adds ONLY the three abstract metadata
///         getters and a test-only `mint`; it changes none of the authorization logic.
///
///         Solady is an independent implementation (not OpenZeppelin) the wal detectors were NOT
///         tuned against - a genuine `holdout` precision test: the harness must stay silent
///         (BLOCKED) on this unseen safe code.
contract SoladyNFTFixture is ERC721 {
    function name() public pure override returns (string memory) {
        return "Solady Safe NFT (holdout)";
    }

    function symbol() public pure override returns (string memory) {
        return "SSN";
    }

    function tokenURI(uint256) public pure override returns (string memory) {
        return "";
    }

    /// @dev Test-only mint to fund a holder for the offline safe-behavior check.
    function mint(address to, uint256 id) external {
        _mint(to, id);
    }
}
