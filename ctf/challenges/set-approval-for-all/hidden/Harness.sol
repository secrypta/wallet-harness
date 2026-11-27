// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the set-approval-for-all gate.

/// @dev Minimal ERC-721 with the approval surface the vector needs.
contract MockERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function approve(address to, uint256 tokenId) external {
        require(
            msg.sender == ownerOf[tokenId] || isApprovedForAll[ownerOf[tokenId]][msg.sender],
            "ERC721: not authorized to approve"
        );
        getApproved[tokenId] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "ERC721: wrong owner");
        require(
            msg.sender == from
                || getApproved[tokenId] == msg.sender
                || isApprovedForAll[from][msg.sender],
            "ERC721: caller is not token owner or approved"
        );
        ownerOf[tokenId] = to;
        getApproved[tokenId] = address(0);
    }
}

/// @dev The operator the wallet authorizes. Legit use pulls the agreed token; the attack
///      tries to pull a different one.
contract Operator {
    function pull(address nft, address from, uint256 tokenId) external {
        MockERC721(nft).transferFrom(from, address(this), tokenId);
    }
}
