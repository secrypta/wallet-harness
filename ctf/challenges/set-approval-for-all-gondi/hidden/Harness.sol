// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the Gondi gate. No imports from the corpus / fixtures /
// vendor - the CTF is decoupled from the harness core by code.

/// @dev Minimal ERC-721 with the operator-approval surface the vector needs.
contract MockERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "ERC721: wrong owner");
        require(
            msg.sender == from || isApprovedForAll[from][msg.sender],
            "ERC721: caller is not token owner or approved"
        );
        ownerOf[tokenId] = to;
    }
}
