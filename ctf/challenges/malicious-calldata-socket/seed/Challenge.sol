// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - minimized Socket Gateway route with arbitrary-call injection.
/// @notice This is the VULNERABLE version. Your job is to fix `performAction` so the
///         call-injection drain (Socket Gateway, 2024-01-16) can no longer spend users'
///         standing approvals, WITHOUT breaking legitimate routing.
///
///         Keep the `performAction` signature exactly as-is - the hidden grader calls it by
///         this name and arguments. You may change only its body.
///
///         The bug: `fromToken` (the call target) and `swapExtraData` (the calldata) are taken
///         straight from the caller and executed unvalidated. An attacker sets the target to a
///         victim's approved token and the calldata to `transferFrom(victim, attacker, amount)`;
///         it runs with msg.sender == this gateway, spending the victim's approval. The only
///         post-call check compares the native-ETH balance delta to `amount`, so `amount = 0`
///         slips past it regardless of what token function actually ran.
contract Challenge {
    /// @notice The one audited route implementation this gateway is meant to call. Immutable.
    address public immutable trustedRoute;

    constructor(address trustedRoute_) {
        trustedRoute = trustedRoute_;
    }

    function performAction(address fromToken, uint256 amount, bytes calldata swapExtraData)
        external
        payable
    {
        uint256 balanceBefore = address(this).balance - msg.value;

        // BUG: unvalidated caller-supplied target + calldata.
        (bool ok, ) = fromToken.call(swapExtraData);
        require(ok, "route call failed");

        // Wrong invariant: only checks native-ETH movement. amount = 0 always passes.
        require(address(this).balance - balanceBefore == amount, "eth balance check");
    }
}
