// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./dexible-selfswap-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Dexible (DEX aggregator) exploit, 2023-02-17, Ethereum (+Arbitrum), ~$2M from
//            17 trader addresses that had approved Dexible as a spender. The v2 `selfSwap`
//            path let a user supply a `router` address and arbitrary `routerData` (calldata)
//            for a swap, with NO on-chain check that the router was a legitimate DEX router.
//            The attacker set the router to a victim's token and routerData to
//            transferFrom(victim, attacker, amount); the call ran with msg.sender == Dexible,
//            so the token honored it against the victim's standing approval.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable selfSwap path: a
//            caller-supplied call target + calldata executed by the contract with no router
//            validation and no post-call guard. The real fee/EIP-712 fill plumbing is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6
//                       from  0x684083f312ac50f538cc4b634d85a2feafaab77a (attacker EOA)
//                       to    0x194fc30f9eeba9ad673413629b47fc00e71d90df (attack contract)
//                       block 16646023 (Ethereum), 2023-02-17 04:20:35 UTC.
//   Sources: PeckShield; BlockApex; cryptonews; blockchain.news; Dexible post-mortem
//            (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title DexibleClone - minimized Dexible selfSwap with an unvalidated router + calldata.
/// @notice VULNERABLE: selfSwap executes a caller-supplied `router` with caller-supplied
///         `routerData` and performs no check that `router` is a real DEX router (no
///         whitelist) and no guard on what the call did. The attacker sets `router` to a
///         victim's approved token and `routerData` to transferFrom(victim, attacker, amount);
///         the call runs as msg.sender == this contract and drains the standing approval.
///         Plainest form of the arbitrary-external-call injection class.
contract DexibleClone {
    /// @param router      caller-chosen call target (the incident: a victim's approved token)
    /// @param routerData  caller-chosen calldata (the incident: an abi-encoded transferFrom)
    function selfSwap(address router, bytes calldata routerData) external {
        // No router whitelist, no post-call accounting: the call target and payload are fully
        // attacker-controlled and executed with this contract's authority.
        (bool ok, ) = router.call(routerData);
        require(ok, "swap call failed");
    }
}
