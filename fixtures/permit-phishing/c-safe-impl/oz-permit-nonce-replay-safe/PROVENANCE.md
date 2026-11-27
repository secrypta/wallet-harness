# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/oz-permit-nonce-replay-safe
Vector:       permit-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        dev                       # OZ is the reference impl (not an independent holdout)
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts - the canonical EIP-2612 ERC20Permit implementation,
              backed by OZ `Nonces`.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files token/ERC20/extensions/ERC20Permit.sol, utils/Nonces.sol,
              utils/cryptography/{EIP712,ECDSA}.sol -> vendored byte-identical under
              fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  reuses oz-permit-safe/OZERC20PermitFixture.sol (concrete token over unmodified
              OZ ERC20 + ERC20Permit).

Distinct property: proves the NONCE / anti-REPLAY property of real OZ permit. `permit` consumes
             the owner's nonce via `_useNonce(owner)` on first use; replaying the same captured
             signature recomputes the digest with the NEW (incremented) nonce, so ECDSA recovers
             a different signer and OZ reverts `ERC2612InvalidSigner`. Models the "capture the
             phished permit signature and resubmit it" sub-attack: the real code lets it work at
             most once, and a replay cannot re-grant allowance.

Behavior:    test/RealSafePermitRound4.t.sol signs a bounded permit, submits it once (allowance
             set, nonce bumped 0 -> 1), then REPLAYS the identical signature - the real OZ code
             reverts ERC2612InvalidSigner. Confirms the replay granted no new allowance and the
             balance beyond the single bounded spend is intact. The verdict is derived from the
             real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
