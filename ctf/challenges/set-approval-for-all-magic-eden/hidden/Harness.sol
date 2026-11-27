// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the Magic Eden gate. No imports from the corpus / fixtures /
// vendor - the CTF is decoupled from the harness core by code. These model the incident's two
// supporting contracts: an ERC-721 and a CORRECT ERC-2771 payment processor. The fixable defect
// is in the forwarder (src/Challenge.sol), not here.

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

/// @dev The payment processor. It is a CORRECT ERC-2771 consumer: it only strips the appended
///      sender when the caller is its trusted forwarder. It settles a sale by pulling the acting
///      seller's NFT (seller = `_msgSender()`) to `to`, relying on the seller's standing operator
///      approval - exactly as the real processor did. It has no bug of its own; it simply trusts
///      whatever `_msgSender()` the forwarder authenticated.
contract PaymentProcessor {
    address public trustedForwarder;

    constructor(address forwarder_) {
        trustedForwarder = forwarder_;
    }

    function _msgSender() internal view returns (address signer) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly {
                signer := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            signer = msg.sender;
        }
    }

    function sellNft(address nft, uint256 tokenId, address to) external {
        address seller = _msgSender();
        MockERC721(nft).transferFrom(seller, to, tokenId);
    }
}
