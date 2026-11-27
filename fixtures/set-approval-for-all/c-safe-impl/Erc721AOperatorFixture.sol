// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721A} from "../../vendor/erc721a/contracts/ERC721A.sol";

/// @title Erc721AOperatorFixture - concrete NFT over the UNMODIFIED vendored ERC721A (Chiru Labs).
/// @notice Real-safe HOLDOUT vehicle for the set-approval-for-all vector. The operator-for-all /
///         per-token transfer authorization that stops a sweep by a non-approved operator is
///         ERC721A's unmodified code (fixtures/vendor/erc721a/contracts/ERC721A.sol, MIT, pinned
///         tag v4.3.0; see fixtures/vendor/PROVENANCE.md). This subclass adds ONLY name()/symbol()
///         via the constructor and a test-only sequential `mint`; it changes none of the
///         authorization logic.
///
///         Distinct from the existing set-approval holdouts (OZ ERC721 / OZ ERC1155 / Solady
///         ERC721 / Solady ERC1155): ERC721A is an INDEPENDENT, widely-deployed NFT codebase with
///         a materially different internal design - packed sequential ownership and batch minting,
///         with its own `_operatorApprovals` map and its own transfer-authorization path
///         (`transferFrom` -> `_isSenderApprovedOrOwner` || `isApprovedForAll`). It is real "wild"
///         code the harness was never tuned against, exercising the canonical `setApprovalForAll`
///         authorization on a third, independent implementation: an operator that was NOT granted
///         approval-for-all cannot move the holder's tokens.
contract Erc721AOperatorFixture is ERC721A {
    constructor() ERC721A("ERC721A Safe NFT (holdout)", "ASN") {}

    /// @dev Test-only sequential mint (ERC721A mints `quantity` tokens from `_startTokenId()`).
    function mint(address to, uint256 quantity) external {
        _mint(to, quantity);
    }
}
