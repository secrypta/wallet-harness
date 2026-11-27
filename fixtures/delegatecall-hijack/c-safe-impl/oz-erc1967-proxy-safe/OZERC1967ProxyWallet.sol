// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the delegatecall-hijack vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// A legitimate ERC-1967 / UUPS proxy USES `delegatecall` as its core mechanism: the proxy
// forwards every call to the implementation recorded in its ERC-1967 implementation slot via
// `delegatecall` (OZ `Proxy._delegate` -> `ERC1967Utils.getImplementation()`). The
// delegatecall-hijack vector (Parity/Bybit) is NOT "a contract uses delegatecall" - it is
// "an owner-approved operation delegatecalls a CALLER-CHOSEN target, so attacker code runs in
// the wallet's own storage and rewrites its owner/implementation". The canonical proxy has no
// such sink:
//   * the only delegatecall target is the MANAGED implementation slot, never caller input;
//   * changing that slot (`upgradeToAndCall`) is gated by UUPS `_authorizeUpgrade` (owner);
//   * owner-approved operations run through `execute`, which uses a PLAIN `call` - there is no
//     "delegatecall operation mode" to request attacker-context execution.
// This fixture is a PRECISION check: a real proxy's delegatecall-to-its-implementation must
// NOT be flagged as a delegatecall-hijack.
//
// The only code authored here on top of the unmodified OZ UUPS base is this thin wallet: a
// stored `owner`, an owner-gated `_authorizeUpgrade`, and an owner-only `execute` that uses a
// plain `call`. None of OZ's proxy/upgrade logic is modified.

import {UUPSUpgradeable} from "../../../vendor/oz/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "../../../vendor/oz/proxy/utils/Initializable.sol";

/// @title OZERC1967ProxyWallet - a minimal UUPS wallet implementation behind an ERC1967Proxy.
/// @notice Runs behind `ERC1967Proxy`; the proxy delegatecalls ONLY this managed implementation.
contract OZERC1967ProxyWallet is Initializable, UUPSUpgradeable {
    address public owner;
    uint256 public version;

    /// @dev The implementation itself must never be initialized directly.
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        owner = owner_;
        version = 1;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @notice Owner-approved operation, executed via a PLAIN `call`. There is deliberately no
    ///         delegatecall operation mode: a routed target runs in ITS OWN context, so it can
    ///         never rewrite this wallet's `owner`/implementation (the Parity/Safe hijack).
    function execute(address to, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    /// @dev UUPS upgrade authorization - only the owner may change the (delegatecall) target.
    function _authorizeUpgrade(address) internal view override onlyOwner {}
}

/// @title OZERC1967ProxyWalletV2 - a benign upgrade used to prove upgrades still work (non-vacuous).
contract OZERC1967ProxyWalletV2 is Initializable, UUPSUpgradeable {
    address public owner;
    uint256 public version;

    constructor() {
        _disableInitializers();
    }

    function reinit() external reinitializer(2) {
        version = 2;
    }

    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == owner, "not owner");
    }
}
