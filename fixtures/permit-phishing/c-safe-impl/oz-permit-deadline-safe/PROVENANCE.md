# Fixture provenance

```
Fixture:      permit-phishing/c-safe-impl/oz-permit-deadline-safe
Vector:       permit-phishing
Tier:         c-safe-impl (genuinely-safe real code)
Split:        dev                       # OZ is the reference impl (not an independent holdout)
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin Contracts - the canonical EIP-2612 ERC20Permit implementation.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files token/ERC20/extensions/ERC20Permit.sol, utils/cryptography/EIP712.sol,
              utils/cryptography/ECDSA.sol, utils/Nonces.sol -> vendored byte-identical under
              fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in fixtures/vendor/oz/LICENSE.
Source code:  reuses oz-permit-safe/OZERC20PermitFixture.sol (a concrete token over the
              unmodified OZ ERC20 + ERC20Permit; adds only name/symbol + a test-only mint).

Distinct property: oz-permit-safe proves the bounded-ALLOWANCE property (a bounded permit cannot
             over-draw). THIS fixture proves the DEADLINE property: OZ `permit` checks
             `block.timestamp > deadline` first and reverts `ERC2612ExpiredSignature` before any
             allowance is set. Models a phished/stale permit signature that is submitted after
             its deadline - the real OZ code rejects it, so no allowance is ever granted.

Behavior:    test/RealSafePermitRound4.t.sol signs a FULL-balance permit with a deadline already
             in the past, submits it (reverts ERC2612ExpiredSignature), confirms allowance stays
             0 and a drain reverts. Guard: the same flow with a VALID deadline and a BOUNDED value
             succeeds for exactly that amount - so the revert is genuinely the deadline check, not
             broken code. The verdict is derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed.
```
