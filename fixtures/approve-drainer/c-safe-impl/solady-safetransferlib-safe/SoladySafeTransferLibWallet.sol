// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SafeTransferLib} from "../../../vendor/solady-accounts/utils/SafeTransferLib.sol";

/// @title SoladySafeTransferLibWallet - scoped-approval wallet over the REAL Solady SafeTransferLib.
/// @notice Tier-(c) real-safe HOLDOUT vehicle for the approve-drainer vector. The approval
///         mechanism under test is Solady's unmodified `SafeTransferLib.safeApprove`
///         (fixtures/vendor/solady-accounts/utils/SafeTransferLib.sol, MIT, Vectorized/solady
///         v0.1.22, commit 65e87c72a5ee4a6708946b25611ec5f980ceba70; byte-identical, see
///         fixtures/vendor/PROVENANCE.md). This wallet adds ONLY two thin entrypoints over that
///         library:
///           - `scopedApprove`: grant a spender EXACTLY `amount` (never `type(uint256).max`),
///           - `revoke`: reset that allowance back to zero after the interaction,
///         i.e. the canonical "approve exactly what the interaction needs, then revoke" pattern
///         a careful integrator uses. The over-draw revert itself comes from the real ERC-20
///         allowance accounting of the token the wallet holds (Solady ERC20 in the proof test).
///
///         Solady is an independent codebase the wal detectors were NEVER tuned against, so a
///         clean verdict here is an honest precision signal, not "our own safe code passing our
///         own harness". The harness MUST stay silent (verdict BLOCKED, label safe); a
///         VULNERABLE here would be a real, recorded false positive.
///
///         Built/run only inside Docker (see harness/run.sh). Never deploy to a real network.
contract SoladySafeTransferLibWallet {
    using SafeTransferLib for address;

    /// @notice Grant `spender` a BOUNDED allowance of exactly `amount` over `token` held by
    ///         this wallet - never an unbounded (max) approval. Uses the real Solady
    ///         `safeApprove`, which reverts if the underlying `approve` fails.
    function scopedApprove(address token, address spender, uint256 amount) external {
        token.safeApprove(spender, amount);
    }

    /// @notice Revoke `spender`'s allowance (reset to zero) so no lingering drain surface is
    ///         left after the interaction completes.
    function revoke(address token, address spender) external {
        token.safeApprove(spender, 0);
    }
}
