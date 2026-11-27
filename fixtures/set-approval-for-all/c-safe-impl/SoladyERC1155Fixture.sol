// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "../../vendor/solady/ERC1155.sol";

/// @title SoladyMultiTokenFixture - concrete ERC-1155 over the UNMODIFIED vendored Solady ERC1155.
/// @notice Real-safe HOLDOUT vehicle for the set-approval-for-all vector. The operator
///         authorization that stops a sweep by a non-approved operator is Solady's unmodified
///         `ERC1155` (fixtures/vendor/solady/ERC1155.sol, MIT, pinned commit; see
///         fixtures/vendor/PROVENANCE.md). This subclass adds ONLY the abstract `uri` getter and a
///         test-only `mint`; it changes none of the authorization logic.
///
///         Distinct from the existing holdouts: `oz-erc1155-safe` exercises the SAME ERC-1155
///         operator-for-all model on OpenZeppelin, and `solady-erc721-safe` exercises Solady's
///         ERC-721 (per-token) model. This fixture closes the remaining {Solady} x {ERC-1155}
///         cell - the ERC-1155 operator model on the independent Solady codebase the wal
///         detectors were NEVER tuned against (a genuine `holdout` precision test: the harness
///         must stay silent, BLOCKED, on this unseen safe code).
contract SoladyMultiTokenFixture is ERC1155 {
    function uri(uint256) public pure override returns (string memory) {
        return "";
    }

    /// @dev Test-only mint to fund a holder for the offline safe-behavior check.
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }
}
