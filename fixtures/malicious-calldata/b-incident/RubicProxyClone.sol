// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./rubic-router-whitelist-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Rubic Exchange (cross-chain DEX aggregator) exploit, 2022-12-25, Ethereum,
//            ~$1.4M drained from users who had approved the RubicProxy. The proxy forwarded
//            swaps by low-level-calling a "router" with caller-supplied calldata, gated only
//            by a router whitelist. The team had MISTAKENLY added a TOKEN (USDC) to that
//            whitelist, so the attacker passed the token as the "router" and supplied
//            transferFrom(victim, attacker, amount) as the calldata; the proxy executed it
//            as msg.sender and pulled victims' standing approvals.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable forward-call path: a
//            whitelist that fails to distinguish a token from a router, plus caller-supplied
//            calldata executed by the proxy. The real multi-provider routing is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x9a97d85642f956ad7a6b852cf7bed6f9669e2c2815f3279855acf7f1328e7d46
//                       from  0x001b91c794dfeecf00124d3f9525dd32870b6ee9 (attacker EOA)
//                       to    0x253dd81d642220267ccac1d8202c0b96a92b299e (attack contract)
//                       block 16260581 (Ethereum), 2022-12-25 08:31:11 UTC.
//   Sources: PeckShield; BlockSec; QuillAudits; SolidityScan; DcentraLab (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title RubicProxyClone - minimized Rubic forward-call proxy with a token in the whitelist.
/// @notice VULNERABLE: routerCall forwards caller-supplied calldata to a `router` as long as
///         `router` is whitelisted. The only guard is the whitelist, and in the incident a
///         TOKEN address was mistakenly whitelisted. Because the whitelist does not prove the
///         target is a benign router (vs. an ERC-20), the attacker uses the token as `router`
///         and transferFrom(...) as the calldata; the proxy runs it as msg.sender and drains
///         standing approvals. Arbitrary-call injection gated by an insufficient allowlist.
contract RubicProxyClone {
    mapping(address => bool) public isWhitelisted;

    /// @notice In the real incident an admin op added USDC (a token) to the router whitelist.
    ///         Modeled as a plain setter so the test can reproduce that exact misconfiguration.
    function setWhitelisted(address target, bool ok) external {
        isWhitelisted[target] = ok;
    }

    /// @param router  a whitelisted call target (the incident: a mistakenly whitelisted token)
    /// @param data    caller-supplied calldata (the incident: an abi-encoded transferFrom)
    function routerCall(address router, bytes calldata data) external {
        require(isWhitelisted[router], "router not whitelisted");
        // Whitelist is the ONLY check; the calldata itself is never constrained, so a
        // whitelisted token lets the attacker run transferFrom with the proxy as msg.sender.
        (bool ok, ) = router.call(data);
        require(ok, "router call failed");
    }
}
