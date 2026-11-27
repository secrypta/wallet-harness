// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./PROVENANCE.md for the full block)
//   Vector:  upgrade-governance   Tier: c-safe-impl   Expected: BLOCKED
//   Pairs with: upgrade-governance/b-incident/wormhole-uninit-impl-victim (the SAME system,
//               secure/post-fix state) - the "vulnerable -> safe" pair the standard asks for.
//   Nature:  MINIMIZED CLONE of Wormhole's REAL secure (post-fix) state, authored by us (MIT),
//            mirroring Wormhole's genuine-distinct re-initialization guard. NOT OpenZeppelin
//            `Initializable` (a single-slot counter): Wormhole keys an initialization flag PER
//            IMPLEMENTATION in `mapping(address => bool) initializedImplementations`, read by
//            `isInitialized(impl)` / written by `setInitialized(impl)`, and the `initializer`
//            modifier keys it on `ERC1967Upgrade._getImplementation()`. This standalone
//            minimized logic contract keys the same flag on `address(this)` (the implementation
//            an attacker targets when calling `initialize()` directly on the logic contract).
//   Incident & fix (authoritative):
//            Wormhole uninitialized-implementation bug, disclosed 2022-02-24 by whitehat
//            satya0x; $10,000,000 Immunefi bounty. An earlier bugfix had reverted the
//            implementation's initialization, leaving the implementation contract
//            (0x736d2a394f7810c17b3c6fed017d5bc7d60c077d) UNINITIALIZED, so anyone could call
//            `initialize()` on it, seize the guardian set, and drive the guardian-only
//            `submitContractUpgrade` (a delegatecall migration that could selfdestruct/brick
//            the proxy). THE FIX was a single transaction
//            (0x9acb2b580aba4f5be75366255800df5f62ede576619cb5ce638cedc61273a50f) that called
//            `initialize()` on the implementation and set the Guardians - initializing (locking)
//            the implementation. Wormhole's per-implementation `initializedImplementations`
//            guard (present in its design since 2021) then makes the initialized implementation
//            non-seizable: any further `initialize()` reverts "already initialized".
//   Source:  github.com/wormhole-foundation/wormhole (Apache-2.0), ethereum/contracts/
//            {Implementation,Getters,Setters}.sol at main commit
//            c7029ab06566c707f6ba89539ce9b24bbfc009ef (blobs Implementation 5bb98cf8,
//            Getters 627b6415, Setters 17f88282). Attribution: Copyright 2022 Wormhole Project
//            Contributors, Apache-2.0. No third-party bytecode copied; this is our own MIT clone
//            of the mechanism, not a vendored file.
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title WormholeInitGuardSafe - minimized clone of Wormhole's SECURE (post-fix) core
///        implementation: the implementation is initialized (locked) and a per-implementation
///        re-initialization guard blocks any takeover.
/// @notice SAFE counterpart of wormhole-uninit-impl-victim. In the incident the implementation
///         was left UNINITIALIZED, so an attacker's first `initialize()` won and seized the
///         guardian-only upgrade path. Here the implementation ships INITIALIZED (as the fix
///         tx ensured) and the per-implementation `initializedImplementations` guard reverts
///         any further `initialize()`, so no attacker can seize the guardian - the
///         guardian-only `submitContractUpgrade` stays with the legitimate guardian. The
///         privileged path still works for the rightful guardian (non-vacuous).
contract WormholeInitGuardSafe {
    /// @dev Mirrors Wormhole `State.initializedImplementations` - a PER-IMPLEMENTATION flag,
    ///      not a single global counter. This is the genuine-distinct mechanism (vs. OZ
    ///      `Initializable`'s single-slot `_initialized`).
    mapping(address => bool) private initializedImplementations;

    address public guardian; // the privileged controller set by initialize()
    address public implementation; // the upgrade pointer a takeover would weaponize

    /// @notice Mirrors Wormhole `Getters.isInitialized(address impl)`.
    function isInitialized(address impl) public view returns (bool) {
        return initializedImplementations[impl];
    }

    /// @notice Mirrors Wormhole `Setters.setInitialized(address impl)`.
    function _setInitialized(address impl) internal {
        initializedImplementations[impl] = true;
    }

    /// @dev Wormhole keys this on `ERC1967Upgrade._getImplementation()`. This standalone
    ///      minimized logic contract keys it on `address(this)` - the implementation an
    ///      attacker targets when calling `initialize()` directly on the logic contract.
    function _implementationId() internal view returns (address) {
        return address(this);
    }

    /// @notice Mirrors Wormhole `Implementation.initializer` - a per-implementation one-shot.
    modifier initializer() {
        address impl = _implementationId();
        require(!isInitialized(impl), "already initialized");
        _setInitialized(impl);
        _;
    }

    /// @notice Legitimate setup initializes (locks) the implementation and sets the guardian.
    ///         This is the step the incident FAILED to perform (leaving the impl open) and that
    ///         the fix tx 0x9acb... performed. Guarded one-shot per implementation: after it
    ///         runs, any further `initialize()` reverts, so an attacker can never seize control.
    function initialize(address guardian_) external initializer {
        guardian = guardian_;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "not guardian");
        _;
    }

    /// @notice Guardian-only upgrade path (the privileged action a takeover would weaponize).
    ///         Stays with the legitimate guardian because the implementation cannot be
    ///         re-initialized to install an attacker-controlled guardian.
    function submitContractUpgrade(address newImplementation) external onlyGuardian {
        implementation = newImplementation;
    }

    /// @notice Convenience view mirroring the incident fixture's `initialized()` surface.
    function initialized() external view returns (bool) {
        return isInitialized(_implementationId());
    }
}
