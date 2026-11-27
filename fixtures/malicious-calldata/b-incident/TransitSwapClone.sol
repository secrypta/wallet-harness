// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./transit-claimtokens-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Transit Swap (cross-chain DEX aggregator) exploit, 2022-10-01, BNB Chain
//            (also Ethereum), >$21M drained from users who had approved the router. The
//            router routed token pulls through a transfer helper whose claimTokens(token,
//            from, to, amount) ran transferFrom(from, to, amount) with the `from` (token
//            OWNER) taken straight from the caller and NEVER validated against msg.sender.
//            The attacker named innocent users who had granted the router an approval as
//            `from` and set `to` to themselves, so the router pulled those users' balances.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable transfer-helper path:
//            an unvalidated caller-supplied `from` on a transferFrom the contract performs
//            against standing approvals. The real multi-hop swap/bridge routing is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x181a7882aac0eab1036eedba25bc95a16e10f61b5df2e99d240a16c334b9b189
//                       from  0x5f0b31aa37bce387a8b21554a8360c6b8698fbef (attacker EOA)
//                       to    0x8ca8fd9c7641849a14cbf72faf05c305b0c68a34 (attack contract)
//                       block 21816546 (BNB Chain), 2022-10-01 18:35:54 UTC.
//            TransitSwap router (victim entry): 0x8785bb8deae13783b24d7afe250d42ea7d7e9d72;
//            transfer helper (ran transferFrom): 0xed1afc8c4604958c2f38a3408fa63b32e737c428.
//   Sources: SlowMist; Numen Cyber; QuillAudits; SharkTeam; Beosin (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title TransitSwapClone - minimized Transit Swap transfer-helper with an unvalidated owner.
/// @notice VULNERABLE: claimTokens pulls `amount` of `token` from `from` to `to` via
///         transferFrom, but `from` (the token owner) is supplied by the caller and is never
///         checked against msg.sender. Because the pull runs with msg.sender == this router -
///         which users had granted ERC-20 approvals - anyone can name a victim as `from` and
///         drain that victim's standing approval. This is the arbitrary-call / unvalidated-
///         parameter class: the attacker controls whose funds the privileged contract moves.
contract TransitSwapClone {
    /// @param token   the ERC-20 to pull (the incident: a token victims had approved)
    /// @param from    caller-chosen token owner - UNVALIDATED (should be msg.sender)
    /// @param to      recipient (the incident: the attacker)
    /// @param amount  amount to pull against `from`'s approval to this router
    function claimTokens(address token, address from, address to, uint256 amount) external {
        // No `require(from == msg.sender)` - the core defect. The router moves a third
        // party's funds purely on caller-supplied parameters.
        IERC20Like(token).transferFrom(from, to, amount);
    }
}
