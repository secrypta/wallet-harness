// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "../../vendor/oz/token/ERC721/ERC721.sol";

/// @title OzERC721OperatorFixture - concrete NFT over the UNMODIFIED vendored OpenZeppelin ERC721.
/// @notice Real-safe HOLDOUT vehicle for the set-approval-for-all vector. The operator-for-all /
///         per-token authorization that stops a sweep by a non-approved operator is OpenZeppelin's
///         unmodified `ERC721` (fixtures/vendor/oz/token/ERC721/ERC721.sol, MIT, pinned v5.1.0; see
///         fixtures/vendor/PROVENANCE.md). This subclass adds ONLY name()/symbol() via the
///         constructor and a test-only `mint`; it changes none of the authorization logic.
///
///         Distinct from the existing set-approval holdouts: `oz-erc1155-safe` is the OZ ERC-1155
///         operator-for-all model (different token standard) and `solady-erc1155-safe` /
///         `solady-erc721-safe` are the independent Solady codebase. This fixture covers the
///         {OpenZeppelin} x {ERC-721} operator-for-all cell as a scored holdout - the canonical
///         `setApprovalForAll` authorization on OZ's own ERC-721, where an operator that was NOT
///         granted approval-for-all cannot sweep the holder's tokens.
contract OzERC721OperatorFixture is ERC721 {
    constructor() ERC721("OZ Safe NFT (holdout)", "OSN") {}

    /// @dev Test-only mint to fund a holder for the offline safe-behavior check.
    function mint(address to, uint256 id) external {
        _mint(to, id);
    }
}
