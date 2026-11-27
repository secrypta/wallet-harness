# Fixture provenance

```
Fixture:      blind-eth-sign/c-safe-impl/oz-votes-delegatebysig-safe
Vector:       blind-eth-sign
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout
Expected:     safe

Origin:       OpenZeppelin ERC20Votes / Votes.delegateBySig - the canonical governance
              delegation-by-signature surface (ERC-5805 / typed EIP-712 Delegation).
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files token/ERC20/extensions/ERC20Votes.sol + governance/utils/Votes.sol + closure
              -> vendored byte-identical at fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  ../OzVotesTokenFixture.sol (concrete ERC20Votes token; adds only a test-only mint +
              constructor - no change to the delegation/signature logic).

Why holdout: The existing blind-eth-sign holdouts are a wallet gate (OZ EIP712+ECDSA), Uniswap
             Permit2, and Solady EIP712+SignatureCheckerLib. This fixture exercises a different real
             surface: governance delegation-by-signature (OZ Votes), where a blind eth_sign cannot
             redirect an account's voting power because the signature must cover the typed
             Delegation digest. Unseen safe code wal was never tuned against.

Behavior:    test/RealSafeVotesDelegateBySigHoldout.t.sol has a victim self-delegate (holding their
             own votes), then the phisher uses a BLIND eth_sign (personal_sign over an opaque hash)
             in delegateBySig to try to redirect the victim's votes to the attacker. ECDSA.recover
             over the typed Delegation digest yields a signer OTHER than the victim, so the victim's
             delegation is untouched and the attacker gains no votes. A guard shows a genuine typed
             Delegation signature DOES delegate. Verdict derived from the real outcome.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
             Precision-side safe holdout (no independent code-level vuln blind-eth-sign incident at
             the bar not already used elsewhere); stated plainly, not padded.
```
