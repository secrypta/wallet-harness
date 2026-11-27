// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "../../vendor/oz/token/ERC1155/ERC1155.sol";

/// @title OzScopedERC1155 - a concrete token over the UNMODIFIED OpenZeppelin v5.1.0 `ERC1155`,
///        the real-safe (tier c) vehicle for the set-approval-for-all vector on the ERC-1155
///        operator-for-all surface.
/// @notice ERC-1155 exposes the same blanket `setApprovalForAll(operator, true)` authority as
///         ERC-721; the vector is a holder tricked into granting it to a malicious operator who
///         then `safeTransferFrom`/`safeBatchTransferFrom`-sweeps the whole balance. The
///         operator-authorization logic exercised here (`_update` / `safeTransferFrom` requiring
///         `isApprovedForAll` for a third-party operator) is unmodified OpenZeppelin, vendored
///         byte-identical under fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md). This
///         subclass adds ONLY a test-only `mint`; it changes none of the authorization logic.
///         When the holder has NOT granted operator authority to an attacker, OZ's own check
///         reverts the attacker's transfer, so the harness must stay silent (BLOCKED).
contract OzScopedERC1155 is ERC1155 {
    constructor() ERC1155("https://example.invalid/{id}.json") {}

    /// @notice Test-only mint (no access control) so a holder can be given a balance in one call.
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }
}
