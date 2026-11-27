// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./socket-gateway-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Socket Gateway "arbitrary external call injection", 2024-01-16, Ethereum,
//            ~$3.3M from ~219-230 wallets. A newly added bridge route took the call TARGET
//            (fromToken) and the CALLDATA (swapExtraData) straight from the caller and
//            performed an unvalidated low-level call. The attacker set the target to a token
//            and the calldata to transferFrom(victim, attacker, amount); because the call was
//            made BY the Socket Gateway - which victims had granted standing ERC-20 approvals
//            - the transfer succeeded. A zero `amount` slipped past the only post-call check
//            (it compared the gateway's native-ETH balance delta to `amount`), so the check
//            never confirmed which function actually ran.
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction of the vulnerable route
//            (unvalidated caller-supplied target+calldata + the zero-value balance-check
//            bypass). The real multi-route SocketGateway dispatch is abstracted to the one
//            route the incident turned on.
//   On-chain (verified via read-only RPC, 2026-11-17):
//            Attack tx  0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6
//                       from 0x50df5a2217588772471b84adbbe4194a2ed39066 (attacker EOA),
//                       to   null (deploys the attacker's exploit contract),
//                       block 19021454, 2024-01-16 19:11:23 UTC.
//            SocketGateway (approval target): 0x3a23f943181408eac424116af7b7790c94cb97a5.
//   Sources: Rekt.news; Veridise; CertiK; Beosin; Halborn (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title SocketGatewayClone - minimized Socket Gateway route with arbitrary-call injection.
/// @notice VULNERABLE route: `fromToken` (the call target) and `swapExtraData` (the calldata)
///         are taken directly from the caller and never validated. The gateway performs
///         fromToken.call(swapExtraData), so any function - including transferFrom against a
///         user's standing approval to the gateway - runs with msg.sender == this gateway.
///         The only post-call guard compares the gateway's native-ETH balance delta to
///         `amount`; passing amount = 0 satisfies it regardless of what token function ran.
contract SocketGatewayClone {
    /// @param fromToken      caller-chosen call target (the incident: a victim's approved token)
    /// @param amount         claimed ETH movement; attacker passes 0 to pass the balance check
    /// @param swapExtraData  caller-chosen calldata (the incident: an abi-encoded transferFrom)
    function performAction(address fromToken, uint256 amount, bytes calldata swapExtraData)
        external
        payable
    {
        uint256 balanceBefore = address(this).balance - msg.value;

        // Arbitrary external call injection: unvalidated target + calldata.
        (bool ok, ) = fromToken.call(swapExtraData);
        require(ok, "route call failed");

        // Only validates native-ETH movement == amount. amount = 0 always passes, so the
        // guard never confirms the called function was a legitimate swap.
        require(address(this).balance - balanceBefore == amount, "eth balance check");
    }
}
