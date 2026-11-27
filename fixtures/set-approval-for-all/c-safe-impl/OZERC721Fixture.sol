// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================ PROVENANCE ============================
// Real-safe fixture (validation tier (c)) for the set-approval-for-all vector.
// The safety-relevant logic - operator-for-all / per-token approval and the
// `transferFrom` authorization check (`_isAuthorized`) - is the UNMODIFIED
// OpenZeppelin ERC721:
//   source : github.com/OpenZeppelin/openzeppelin-contracts
//   tag    : v5.1.0
//   commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
//   license: MIT (see fixtures vendor/oz/LICENSE)
// This file adds ONLY a test-only, unguarded `mint` entrypoint and a
// constructor. It changes none of OZ's authorization logic. Never deploy
// this on a real network.
// ====================================================================

import {ERC721} from "../../vendor/oz/token/ERC721/ERC721.sol";

/// @title OZERC721Fixture - a concrete, genuinely-OpenZeppelin ERC-721.
/// @notice Real OZ v5.1.0 ERC721 semantics: `transferFrom` is authorized only
///         for the owner, the single per-token approved operator, or an
///         operator-for-all. A wallet that scopes `approve(operator, tokenId)`
///         to one token therefore leaves every other token un-movable by that
///         operator - which is what makes the scoped-approve flow safe.
contract OZERC721Fixture is ERC721 {
    constructor() ERC721("OZ Fixture NFT", "OZFN") {}

    /// @notice Test-only mint (no access control on purpose; fixtures only).
    ///         Uses `_mint` (not `_safeMint`) so plain wallet contracts need
    ///         not implement IERC721Receiver.
    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}
