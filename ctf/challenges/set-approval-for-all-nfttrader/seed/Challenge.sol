// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721Swap {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title Challenge - the NFTTrader peer-to-peer swap marketplace (VULNERABLE version).
/// @notice Modeled on the NFTTrader drain (2023-12-16, ~$3M; real tx 0xec7523...b393d). Users
///         granted this marketplace a standing operator approval. `completeSwap` moves the
///         opener's NFT to the counterparty with `safeTransferFrom` (which calls the recipient
///         back), then pulls the counterparty's NFT to the opener. The bug: it re-reads the
///         counterparty from storage AFTER the callback, so a reentrant `editCounterparty` can
///         swap in a victim mid-settlement and the second leg pulls the victim's NFT via their
///         lingering operator approval.
///
///         Your job is to fix `completeSwap` so a reentrant change of terms cannot redirect the
///         transfer onto a victim, WITHOUT breaking a normal swap. Keep the signature exactly
///         as-is; change only the body.
contract Challenge {
    struct Swap {
        address opener;
        address openerNft;
        uint256 openerTokenId;
        address counterparty;
        address cpNft;
        uint256 cpTokenId;
        bool active;
    }

    mapping(uint256 => Swap) public swaps;
    uint256 public nextId;

    function createSwap(
        address openerNft,
        uint256 openerTokenId,
        address cpNft,
        uint256 cpTokenId,
        address counterparty
    ) external returns (uint256 id) {
        id = ++nextId;
        swaps[id] = Swap(msg.sender, openerNft, openerTokenId, counterparty, cpNft, cpTokenId, true);
    }

    /// @dev Edit the counterparty terms of an open swap. Reachable mid-settlement (no reentrancy
    ///      guard); only the opener may call it - but the attacker IS the opener.
    function editCounterparty(uint256 swapId, address counterparty, address cpNft, uint256 cpTokenId) external {
        Swap storage s = swaps[swapId];
        require(msg.sender == s.opener, "nfttrader: not opener");
        s.counterparty = counterparty;
        s.cpNft = cpNft;
        s.cpTokenId = cpTokenId;
    }

    function completeSwap(uint256 swapId) external {
        Swap storage s = swaps[swapId];
        require(s.active, "nfttrader: inactive swap");
        s.active = false;
        // Leg 1: opener's NFT to the counterparty. safeTransferFrom calls the recipient back,
        // which is where a reentrant editCounterparty can run.
        IERC721Swap(s.openerNft).safeTransferFrom(s.opener, s.counterparty, s.openerTokenId);
        // Leg 2: BUG - re-reads counterparty/cp token from storage AFTER the callback, so the
        // reentrant edit has already pointed them at a victim.
        IERC721Swap(s.cpNft).transferFrom(s.counterparty, s.opener, s.cpTokenId);
    }
}
