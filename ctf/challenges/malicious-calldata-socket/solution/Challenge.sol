// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the Socket Gateway call-injection drain.
/// @notice The root cause is an unvalidated caller-supplied call target. Allow-list it: the
///         gateway may only call its one audited route implementation, never an arbitrary
///         address such as a victim's token - so a `transferFrom` can no longer be injected
///         against a standing approval. A legitimate routed action still works.
contract Challenge {
    address public immutable trustedRoute;

    constructor(address trustedRoute_) {
        trustedRoute = trustedRoute_;
    }

    function performAction(address fromToken, uint256 amount, bytes calldata swapExtraData)
        external
        payable
    {
        // FIX: only the audited route may be called; an arbitrary target (e.g. a token) is refused.
        require(fromToken == trustedRoute, "route: target not allow-listed");

        uint256 balanceBefore = address(this).balance - msg.value;
        (bool ok, ) = fromToken.call(swapExtraData);
        require(ok, "route call failed");
        require(address(this).balance - balanceBefore == amount, "eth balance check");
    }
}
