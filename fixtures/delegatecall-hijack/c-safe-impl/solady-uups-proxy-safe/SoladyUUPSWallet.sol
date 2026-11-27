// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the delegatecall-hijack vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
//
// Solady `UUPSUpgradeable` is an independent (non-OpenZeppelin) UUPS proxy mixin. Like any
// proxy it USES `delegatecall` as its core mechanism, but only to the implementation recorded
// in the ERC-1967 implementation slot. The delegatecall-hijack vector (Parity/Bybit) is "an
// owner-approved operation delegatecalls a CALLER-CHOSEN target, so attacker code runs in the
// wallet's storage and rewrites owner/implementation" - not "a contract uses delegatecall".
// This wallet has no such sink: the only delegatecall target is the managed implementation
// slot, changing it (`upgradeToAndCall`) is gated by `_authorizeUpgrade` (owner), and owner
// operations run through `execute`, which uses a PLAIN `call` (no delegatecall operation mode).
//
// Distinct from `oz-erc1967-proxy-safe` (OpenZeppelin ERC1967/UUPS, round 4): this is Solady's
// independent UUPS implementation behind an ERC-1967 proxy. The only authored code is this
// thin wallet (stored `owner`, owner-gated `_authorizeUpgrade`, owner-only `execute` via plain
// `call`); none of Solady's upgrade logic is modified.

import {UUPSUpgradeable} from "../../../vendor/solady-accounts/utils/UUPSUpgradeable.sol";

/// @title SoladyUUPSWallet - a minimal UUPS wallet over the unmodified Solady UUPSUpgradeable.
contract SoladyUUPSWallet is UUPSUpgradeable {
    address public owner;
    uint256 public version;

    /// @dev One-shot init (runs in the proxy's storage via the ERC1967Proxy constructor).
    function initialize(address owner_) external {
        require(owner == address(0), "initialized");
        owner = owner_;
        version = 1;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @notice Owner-approved operation executed via a PLAIN `call` (no delegatecall mode).
    function execute(address to, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @dev UUPS upgrade authorization - only the owner may change the delegatecall target.
    function _authorizeUpgrade(address) internal view override onlyOwner {}
}
