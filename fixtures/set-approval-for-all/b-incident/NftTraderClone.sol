// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the NFTTrader.org drain (2023-12-16, ~$3M).
// Authored in THIS repo (MIT). This is NOT a copy of the on-chain NFTTrader contract (which is
// unverified / closed) and NOT a copy of any third-party PoC code. The documented MECHANISM is
// reproduced from authoritative write-ups; see ./nfttrader-operator-victim/PROVENANCE.md for the
// incident facts (attacker, vulnerable contract, tx hash, sources) and the DeFiHackLabs reference
// used to locate them.
//
// Root cause (per SlowMist / Ancilia): victims held a standing `setApprovalForAll(marketplace, true)`
// (blanket operator authority over a whole collection), and the marketplace's swap-settlement
// mutated swap state through a function (`editCounterPart`) that was reachable, WITHOUT reentrancy
// protection, from inside an ERC-721 transfer callback fired mid-settlement. An attacker opened a
// swap offering their own NFT, and during settlement re-entered to set the *victim* as the swap
// counterparty; the marketplace then pulled the victim's NFT with the victim's lingering operator
// approval. The victim never agreed to the swap.

/// @dev Minimal ERC-721 with the operator-for-all authority model that the vector turns on.
contract MiniERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 id) external {
        require(ownerOf[id] == address(0), "exists");
        ownerOf[id] = to;
        unchecked {
            ++balanceOf[to];
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        // Blanket collection-wide authority - the standing grant the drain abuses.
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function _authorized(address owner, address spender) internal view returns (bool) {
        return spender == owner || isApprovedForAll[owner][spender] || getApproved[0] == spender;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "wrong-from");
        require(_authorized(from, msg.sender), "not-authorized");
        ownerOf[id] = to;
        unchecked {
            --balanceOf[from];
            ++balanceOf[to];
        }
    }

    function safeTransferFrom(address from, address to, uint256 id) public {
        transferFrom(from, to, id);
        if (to.code.length != 0) {
            require(
                IERC721Receiver(to).onERC721Received(msg.sender, from, id, "")
                    == IERC721Receiver.onERC721Received.selector,
                "unsafe-recipient"
            );
        }
    }
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

/// @notice Minimized vulnerable swap marketplace. The flaw: `editCounterPart` has no reentrancy
///         guard and no binding to the party that actually consented, so it can be called from a
///         mid-settlement ERC-721 callback to redirect whose NFT the settlement pulls.
contract NftTraderClone is IERC721Receiver {
    struct Swap {
        address maker; // opens the swap, offers `offeredNft`:`offeredId`
        address counterPart; // the party whose `wantedNft`:`wantedId` gets pulled
        MiniERC721 offeredNft;
        uint256 offeredId;
        MiniERC721 wantedNft;
        uint256 wantedId;
        bool open;
    }

    Swap[] public swaps;

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /// @dev Maker escrows the offered NFT into the marketplace; counterPart starts unset.
    function createSwapIntent(MiniERC721 offeredNft, uint256 offeredId, MiniERC721 wantedNft, uint256 wantedId)
        external
        returns (uint256 swapId)
    {
        offeredNft.safeTransferFrom(msg.sender, address(this), offeredId); // escrow
        swaps.push(
            Swap({
                maker: msg.sender,
                counterPart: address(0),
                offeredNft: offeredNft,
                offeredId: offeredId,
                wantedNft: wantedNft,
                wantedId: wantedId,
                open: true
            })
        );
        return swaps.length - 1;
    }

    /// @dev THE FLAW: no reentrancy guard, no check that `cp` consented. Reachable mid-settlement.
    function editCounterPart(uint256 swapId, address cp) external {
        swaps[swapId].counterPart = cp;
    }

    /// @dev Settlement. Returns the escrowed offered NFT to the maker (ERC-721 callback fires on the
    ///      maker here), THEN pulls the counterparty's wanted NFT to the maker. The attacker uses the
    ///      callback to point counterPart at the victim before the pull.
    function closeSwapIntent(uint256 swapId) external {
        Swap storage s = swaps[swapId];
        require(s.open, "closed");
        s.open = false;

        // (1) hand the offered NFT to the maker - safe transfer => onERC721Received on the maker.
        s.offeredNft.safeTransferFrom(address(this), s.maker, s.offeredId);

        // (2) pull the wanted NFT from whoever counterPart now is, using the standing operator grant.
        s.wantedNft.transferFrom(s.counterPart, s.maker, s.wantedId);
    }
}
