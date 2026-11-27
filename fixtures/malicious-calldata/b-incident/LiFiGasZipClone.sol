// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./lifi-gaszip-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  LI.FI / Jumper exploit, 2024-07-16, Ethereum (+Arbitrum), ~$9.73M from 153
//            wallets. A facet (GasZipFacet) added to the LI.FI diamond ~5 days earlier
//            exposed a swap path that performed an external call with caller-supplied call
//            TARGET and CALLDATA without validating them. The attacker set the target to a
//            token and the calldata to transferFrom(victim, attacker, amount); the call ran
//            with msg.sender == the LI.FI diamond, so users who had granted the diamond an
//            INFINITE approval were drained (finite approvals were unaffected).
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction of the unvalidated-swap-call
//            surface (caller-chosen target+calldata -> transferFrom on an infinite approval).
//            The full diamond/facet routing and DEX-aggregator plumbing are abstracted.
//   On-chain (verified via read-only RPC, 2026-11-17):
//            Attack tx  0xd82fe84e63b1aa52e1ce540582ee0895ba4a71ec5e7a632a3faa1aff3e763873
//                       from 0x8b3cb6bf982798fba233bca56749e22eec42dcf3 (attacker EOA),
//                       to   0x986aca5f2ca6b120f4361c519d7a49c5ac50c240 (attacker exploit
//                            contract, which internally called the LI.FI diamond),
//                       block 20318963, 2024-07-16 12:06:35 UTC.
//            LI.FI diamond (victim): 0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae;
//            GasZipFacet: 0xf28a352377663ca134bd27b582b1a9a4dad7e534.
//   Sources: Rekt.news; QuillAudits; BlockSec; SolidityScan; LI.FI post-mortem (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title LiFiGasZipClone - minimized clone of the LI.FI swap facet's arbitrary-call surface.
/// @notice VULNERABLE route: the swap descriptor's `callTo` (target) and `callData` are taken
///         from the caller and executed with no validation that `callTo` is an allow-listed
///         DEX aggregator or that `callData` is a benign swap. The diamond therefore makes
///         arbitrary calls - including transferFrom against users' standing (infinite)
///         approvals to the diamond.
contract LiFiGasZipClone {
    /// @dev Mirrors the facet's swap descriptor (minimized to the exploited fields).
    struct SwapData {
        address callTo; // caller-chosen call target (incident: a victim's approved token)
        address fromToken; // the token being "swapped" (unused in the minimization)
        bytes callData; // caller-chosen calldata (incident: an abi-encoded transferFrom)
    }

    /// @notice The vulnerable swap entrypoint: executes caller-chosen target+calldata.
    function depositToGasZipERC20(SwapData calldata swap) external {
        (bool ok, ) = swap.callTo.call(swap.callData);
        require(ok, "swap call failed");
    }
}
