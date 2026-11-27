// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./unizen-aggregator-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Unizen trade-aggregator exploit, 2024-03-08, Ethereum, ~$2.1M drained from users
//            who had approved the aggregator. Shortly after an upgrade (aimed at lowering gas
//            and raising spending limits), the aggregator's swap flow performed an arbitrary
//            external call WITHOUT binding the token source to msg.sender or restricting the
//            call to trusted DEX routers. The attacker supplied a call to a victim's token
//            with transferFrom(victim, attacker, amount); the aggregator executed it as
//            msg.sender and pulled the victim's standing approval - a confused-deputy drain.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable swap flow: a
//            caller-supplied call target + calldata executed by the aggregator with no
//            source-binding and no router allowlist. The multi-DEX routing is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x923d1d63a1165ebd3521516f6d22d015f2e1b4b22d5dc954152b6c089c765fcd
//                       from  0x2ad8aed847e8d4d3da52aabb7d0f5c25729d10df (attacker EOA)
//                       to    0xd3f64baa732061f8b3626ee44bab354f854877ac (Unizen aggregator proxy)
//                       block 19393770 (Ethereum), 2024-03-08 23:49:35 UTC.
//   Sources: Halborn; Smart Contracts Hacking; BlockSec (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title UnizenAggregatorClone - minimized Unizen aggregator swap with an unbound external call.
/// @notice VULNERABLE: swap executes a caller-supplied `targetDex` with caller-supplied
///         `dexCalldata` and does NOT bind the token source to msg.sender nor restrict the
///         target to trusted routers. The attacker sets targetDex to a victim's approved token
///         and dexCalldata to transferFrom(victim, attacker, amount); the aggregator runs it
///         as msg.sender and drains the standing approval (confused deputy).
contract UnizenAggregatorClone {
    /// @param targetDex    caller-chosen call target (the incident: a victim's approved token)
    /// @param dexCalldata  caller-chosen calldata (the incident: an abi-encoded transferFrom)
    function swap(address targetDex, bytes calldata dexCalldata) external payable {
        // No binding of the token source to msg.sender, no trusted-router allowlist: the call
        // target and payload are fully attacker-controlled and executed with this contract's
        // authority over users' standing approvals.
        (bool ok, ) = targetDex.call(dexCalldata);
        require(ok, "dex call failed");
    }
}
