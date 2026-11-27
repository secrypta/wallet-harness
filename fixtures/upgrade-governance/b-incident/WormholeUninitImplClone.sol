// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./wormhole-uninit-impl-victim/PROVENANCE.md for the full block)
//   Vector:  upgrade-governance   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Wormhole "uninitialized proxy / implementation" bug, disclosed 2022-02-24 by
//            whitehat satya0x; $10,000,000 Immunefi bounty (one of the largest ever). After an
//            earlier bugfix reverted the initialization of the UUPS IMPLEMENTATION contract,
//            the implementation was left UNINITIALIZED. Anyone could call `initialize()` on the
//            implementation directly, take control as a Guardian, and then trigger a
//            SELFDESTRUCT via DELEGATECALL (UUPS `upgradeToAndCall` runs a migration by
//            delegatecall), deleting the proxy and bricking the bridge / locking user funds.
//   Proof:   MECHANISM-LEVEL, NO on-chain ATTACK tx (whitehat disclosure; never exploited).
//            The CONSEQUENCE (selfdestruct-via-delegatecall, unreliable to reproduce offline
//            post-Cancun / EIP-6780) is abstracted to its takeover precondition: an attacker
//            initializes the uninitialized implementation, becomes its guardian, and executes a
//            privileged upgrade action that should have been impossible. Only the resolution
//            (the team calling initialize) is on-chain; there is no attack transaction to pin.
//   Sources: Immunefi bugfix review; Coinspect "Learn EVM Attacks"; r.security Vulnerapedia
//            (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title WormholeCoreImpl - minimized UUPS-style core implementation with the uninitialized-impl flaw.
/// @notice The IMPLEMENTATION contract carries its own `initialized`/`guardian` state. When a
///         proxy delegatecalls it, that state lives in the PROXY's storage (correctly set). But
///         the implementation contract's OWN storage can be left uninitialized - and nothing
///         prevents anyone from calling `initialize()` on the implementation directly to become
///         its guardian, then invoking the guardian-only upgrade path. In Wormhole that upgrade
///         path delegatecalls a migration that could `selfdestruct` the proxy.
contract WormholeCoreImpl {
    bool public initialized;
    address public guardian; // privileged controller
    address public implementation; // the code pointer a takeover weaponizes (brick/drain)

    /// @dev One-shot per contract-storage. On the implementation contract itself this was left
    ///      uncalled, so an attacker can call it directly and seize the implementation.
    function initialize(address guardian_) external {
        require(!initialized, "initialized");
        initialized = true;
        guardian = guardian_;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "not guardian");
        _;
    }

    /// @notice Guardian-only upgrade path. In the incident this delegatecalled a migration that
    ///         could selfdestruct the proxy; here it stands in as the privileged action a
    ///         takeover unlocks (repointing the implementation / bricking the bridge).
    function submitContractUpgrade(address newImplementation) external onlyGuardian {
        implementation = newImplementation;
    }
}
