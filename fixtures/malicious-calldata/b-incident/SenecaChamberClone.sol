// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./seneca-performoperations-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Seneca Protocol exploit, 2024-02-28, Ethereum, ~$6.4M drained from users who had
//            approved the Chamber. The Chamber's `performOperations` entrypoint dispatched a
//            CALL action to an internal `_call(callee, data)` that executed an arbitrary
//            callee with arbitrary calldata and no validation. Because the Chamber held users'
//            ERC-20 approvals, the attacker dispatched a CALL to a victim's token with
//            transferFrom(victim, attacker, amount); it ran with msg.sender == the Chamber and
//            drained the standing approval directly from the user's wallet.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable dispatch: a
//            performOperations entrypoint that reaches an unvalidated arbitrary external call.
//            The real Chamber collateral/debt accounting is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286
//                       from  0x94641c01a4937f2c8ef930580cf396142a2942dc (attacker EOA)
//                       to    0x65c210c59b43eb68112b7a4f75c8393c36491f06 (vulnerable Chamber)
//                       block 19325937 (Ethereum), 2024-02-28 12:09:59 UTC.
//   Sources: Cyfrin; The Block; Cointelegraph; CertiK; BlockSec (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title SenecaChamberClone - minimized Seneca Chamber reaching an arbitrary call.
/// @notice VULNERABLE: performOperations dispatches a CALL action to _call, which executes a
///         caller-supplied callee + calldata with no validation. The Chamber holds users'
///         approvals, so a CALL to a victim's token with transferFrom(...) drains the standing
///         approval with msg.sender == this Chamber. Arbitrary-external-call injection reached
///         through a multi-action batch entrypoint.
contract SenecaChamberClone {
    uint8 public constant ACTION_CALL = 30; // the action id that reached _call in the incident

    /// @notice Batch of operations. The CALL action reaches the unvalidated external call.
    function performOperations(
        uint8[] calldata actions,
        address[] calldata targets,
        bytes[] calldata datas
    ) external payable {
        for (uint256 i; i < actions.length; i++) {
            if (actions[i] == ACTION_CALL) {
                _call(targets[i], datas[i]);
            }
        }
    }

    /// @dev Arbitrary callee + calldata, executed with this contract's authority. No check.
    function _call(address callee, bytes memory data) internal {
        (bool ok, ) = callee.call(data);
        require(ok, "call failed");
    }
}
