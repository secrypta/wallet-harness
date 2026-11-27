// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./rabby-swaprouter-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Rabby Wallet Swap router exploit, 2022-10-11, Ethereum (+BNB Chain), ~$200K
//            (114 ETH + 179 BNB) drained from users who had approved the swap router after
//            Rabby launched its in-wallet Swap feature. The swap contract executed a
//            caller-supplied call TARGET and CALLDATA (via OpenZeppelin's Address
//            functionCallWithValue) with NO validation of either. The attacker pointed the
//            target at victims' tokens and supplied transferFrom(victim, attacker, amount);
//            the router executed it as msg.sender and pulled the victims' standing approvals.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the vulnerable swap path: an
//            unvalidated caller-supplied target+calldata executed by the router against
//            standing approvals. The real multi-DEX swap routing is omitted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attack tx  0x914c1ae4f03657064f0b1d5ddc6e06f39e82bce6fb2f726efdca52c092fbfc26
//                       from  0xb687550842a24d7fbc6aad238fd7e0687ed59d55 (attacker EOA)
//                       to    0x9682f31b3f572988f93c2b8382586ca26a866475 (attacker exploit contract)
//                       block 15724452 (Ethereum), 2022-10-11 11:04:23 UTC.
//            Rabby Swap router (victim): 0x6eb211caf6d304a76efe37d9abdfaddc2d4363d1.
//   Sources: SlowMist; Neptune Mutual; web3isgoinggreat; revoke.cash; Halborn (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title RabbySwapRouterClone - minimized Rabby Swap router with an unvalidated external call.
/// @notice VULNERABLE: swap executes a caller-supplied `swapTarget` with caller-supplied
///         `swapCalldata` (the incident used OZ Address.functionCallWithValue) and validates
///         neither. The attacker points `swapTarget` at a victim's approved token and supplies
///         transferFrom(victim, attacker, amount); the router runs it as msg.sender and drains
///         the standing approval. Arbitrary-external-call injection in an in-wallet swap router.
contract RabbySwapRouterClone {
    /// @param swapTarget    caller-chosen call target (the incident: a victim's approved token)
    /// @param swapCalldata  caller-chosen calldata (the incident: an abi-encoded transferFrom)
    function swap(address swapTarget, bytes calldata swapCalldata) external payable {
        // functionCallWithValue-style: unvalidated target + calldata executed by the router.
        (bool ok, ) = swapTarget.call{value: msg.value}(swapCalldata);
        require(ok, "swap call failed");
    }
}
