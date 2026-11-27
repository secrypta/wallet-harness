// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./hashflow-deprecated-router-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Hashflow exploit, 2023-06-14, Ethereum (+4 other EVM chains), ~$600K-$640K.
//            A DEPRECATED Hashflow contract retained a publicly callable function that still
//            invoked ERC-20 transferFrom against tokens users had left approved to it. Its
//            post-deprecation access-control was inadequate (the function was absent from the
//            audited codebase), so ANY caller could redirect a victim's standing approval and
//            move their tokens to an attacker-chosen recipient. CertiK classes it "Lack of
//            Access Control"; analyses cite the unverified function selector `0x1ce5...`.
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction of the vulnerable surface: a
//            deprecated fill function with no caller authorization that runs transferFrom on a
//            caller-chosen (from, to, amount) using the router's standing approvals. The real
//            multi-function RFQ router is abstracted to the one unauthorized transfer path the
//            incident turned on.
//   On-chain (verified via read-only RPC, 2026-11-19):
//            Attack tx  0xdedda493272b6b35660b9cc9070d2ea32ee61279b821184ff837e0a5752f4042
//                       from 0xbdf38b7475ff810325aa39e988fb80e0aa007e84 (attacker EOA),
//                       to   0xddb19a1bd22c53dac894ee4e2fbfdb0a06769216 (attacker exploit contract),
//                       block 17478994, 2023-06-14.
//            Deprecated Hashflow contract (approval target): 0x79cdFd7Bc46D577b95ed92bcdc8abAba1844Af0c
//                       (per SharkTeam / Etherscan; the attack tx above is the verified artifact).
//   Sources: CertiK post-mortem; SharkTeam analysis; PeckShield (via The Block); revoke.cash;
//            Neptune Mutual (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title HashflowDeprecatedRouterClone - minimized deprecated Hashflow fill path.
/// @notice VULNERABLE: this deprecated helper still invokes `transferFrom` against standing
///         approvals, but has NO caller authorization. Any address can call it and move a
///         victim's approved tokens to an attacker-chosen recipient - the approval-drain the
///         incident abused. (The real contract exposed an unverified function, selector
///         `0x1ce5...`, with the same effect.)
contract HashflowDeprecatedRouterClone {
    /// @param token      the victim's token (approved to this router)
    /// @param from       caller-chosen source (the incident: a victim who approved the router)
    /// @param to         caller-chosen recipient (the incident: the attacker)
    /// @param amount     caller-chosen amount
    function fillRFQT(address token, address from, address to, uint256 amount) external {
        // No access control: the deprecated function still spends standing approvals.
        IERC20Like(token).transferFrom(from, to, amount);
    }
}
