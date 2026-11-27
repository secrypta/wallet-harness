// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// R14 toy pair: reentrancy / CEI approval-reuse drain.
//
// A swap marketplace settles two NFT legs. Users hold a standing setApprovalForAll on the
// marketplace. During settlement the marketplace returns the escrowed NFT with a `safe*`
// transfer, which fires the recipient's ERC-721 callback - a re-entry point. The question the
// R14 rule asks: when the marketplace pulls the *second* leg, does it read the counterparty
// from mutable storage AFTER that callback (drainable), or from a value cached BEFORE it (safe)?
//
//   ReentrantSwapWallet  (vuln)  - reads `swaps[id].counterPart` from storage after the callback;
//                                  editCounterPart (a separate, unguarded entrypoint) can be
//                                  re-entered mid-callback to point it at a victim -> R14 FIRES.
//   CeiCorrectSwapWallet (safe)  - caches the counterparty in a local BEFORE the callback and
//                                  pulls from that local; a mid-callback editCounterPart cannot
//                                  change what is pulled -> R14 SILENT.
//
// Same shape, same `safeTransferFrom`-then-`transferFrom` pair; the ONLY difference is the CEI
// ordering of the counterparty read. This is the discrimination R14 must get right at 0 FP.

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

/// @dev Minimal ERC-721 with the operator-for-all authority the vector abuses. Not an R14 target
///      itself (no re-entry call precedes its transfers).
contract MiniERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 id) external {
        require(ownerOf[id] == address(0), "exists");
        ownerOf[id] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "wrong-from");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not-authorized");
        ownerOf[id] = to;
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

struct Swap {
    address maker;
    address counterPart;
    MiniERC721 offeredNft;
    uint256 offeredId;
    MiniERC721 wantedNft;
    uint256 wantedId;
    bool open;
}

/// @title ReentrantSwapWallet - UNSAFE settlement (CEI violation).
/// @notice `closeSwap` hands back the escrowed NFT (callback) and only THEN reads
///         `swaps[id].counterPart` to pull the wanted NFT. `editCounterPart` is a separate,
///         unguarded entrypoint reachable from the callback, so an attacker redirects the
///         counterparty to a victim mid-settlement and drains the victim's standing approval.
contract ReentrantSwapWallet is IERC721Receiver {
    Swap[] public swaps;

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function createSwap(MiniERC721 offeredNft, uint256 offeredId, MiniERC721 wantedNft, uint256 wantedId)
        external
        returns (uint256 id)
    {
        offeredNft.safeTransferFrom(msg.sender, address(this), offeredId);
        swaps.push(Swap(msg.sender, address(0), offeredNft, offeredId, wantedNft, wantedId, true));
        return swaps.length - 1;
    }

    /// @dev THE FLAW: unguarded, no consent binding, reachable mid-callback.
    function editCounterPart(uint256 id, address cp) external {
        swaps[id].counterPart = cp;
    }

    function closeSwap(uint256 id) external {
        Swap storage s = swaps[id];
        require(s.open, "closed");
        s.open = false;
        // (1) return escrowed NFT to maker -> onERC721Received re-entry point
        s.offeredNft.safeTransferFrom(address(this), s.maker, s.offeredId);
        // (2) pull wanted NFT reading counterPart FROM STORAGE after the callback (drainable)
        s.wantedNft.transferFrom(s.counterPart, s.maker, s.wantedId);
    }
}

/// @title CeiCorrectSwapWallet - SAFE settlement (terms cached before the external call).
/// @notice Identical shape, but the counterparty and token are read into locals BEFORE the
///         `safeTransferFrom` callback, and the pull uses those locals. A mid-callback
///         editCounterPart cannot change what the settlement pulls -> R14 must stay silent.
contract CeiCorrectSwapWallet is IERC721Receiver {
    Swap[] public swaps;

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function createSwap(MiniERC721 offeredNft, uint256 offeredId, MiniERC721 wantedNft, uint256 wantedId)
        external
        returns (uint256 id)
    {
        offeredNft.safeTransferFrom(msg.sender, address(this), offeredId);
        swaps.push(Swap(msg.sender, address(0), offeredNft, offeredId, wantedNft, wantedId, true));
        return swaps.length - 1;
    }

    function editCounterPart(uint256 id, address cp) external {
        swaps[id].counterPart = cp;
    }

    function closeSwap(uint256 id) external {
        Swap storage s = swaps[id];
        require(s.open, "closed");
        s.open = false;
        // CEI: cache every term BEFORE any external call.
        address maker = s.maker;
        address counterPart = s.counterPart;
        MiniERC721 offeredNft = s.offeredNft;
        uint256 offeredId = s.offeredId;
        MiniERC721 wantedNft = s.wantedNft;
        uint256 wantedId = s.wantedId;
        // (1) return escrowed NFT to maker -> callback can re-enter, but cannot change the cached terms
        offeredNft.safeTransferFrom(address(this), maker, offeredId);
        // (2) pull wanted NFT from the CACHED counterparty (not re-read from storage)
        wantedNft.transferFrom(counterPart, maker, wantedId);
    }
}
