# Fixture provenance

```
Fixture:      approve-drainer/c-safe-impl/solady-safetransferlib-safe
Vector:       approve-drainer
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent impl; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady SafeTransferLib - a widely-used, independent MIT ERC20-interaction library
              (the safe approve/transfer wrapper most integrators route token approvals through).
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/utils/SafeTransferLib.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/utils/SafeTransferLib.sol
              (see fixtures/vendor/PROVENANCE.md, "Solady - account-abstraction stack").
              The ERC-20 token the wallet holds is the unmodified Solady ERC20
              (fixtures/vendor/solady/ERC20.sol, same tag; its allowance accounting is what
              reverts the over-draw).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in
              fixtures/vendor/solady-accounts/LICENSE.
Authored here: SoladySafeTransferLibWallet.sol - a thin wallet exposing exactly two entrypoints
              over the UNMODIFIED Solady SafeTransferLib: `scopedApprove` (safeApprove to the
              exact action amount, never max) and `revoke` (safeApprove back to 0). No change to
              any defensive logic; the only code authored here is the two-line approval policy
              and a test harness.

Why holdout: The existing approve-drainer c-safe-impl fixtures use OpenZeppelin (ERC20,
             SafeERC20, ERC4626) and Solady ERC20 directly. This fixture adds the Solady
             SafeTransferLib approval helper as the mechanism under test - a different real
             surface (the approve wrapper integrators actually call), exercised as the canonical
             "approve exactly, then revoke" pattern. A clean verdict is an honest precision
             signal on unseen safe code.

Behavior:    test/RealSafeSafeTransferLibHoldout.t.sol funds the wallet, grants the attacker a
             BOUNDED allowance (10e18) via SafeTransferLib.safeApprove, confirms the attacker can
             pull exactly that much (the authority is real), then:
               (1) a full remaining-balance pull reverts (real ERC-20 allowance accounting), and
               (2) after `revoke`, the allowance is 0 - no lingering drain surface.
             The verdict is derived from the real outcome (balance stays intact), not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.

Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN). A VULNERABLE here
             would be a real false positive and would be recorded as such, not suppressed. The
             incremental real component over solady-erc20-safe is the SafeTransferLib approval
             wrapper + the revoke-to-zero policy; the over-draw revert is the token's allowance
             accounting (stated plainly, not overclaimed as a SafeTransferLib property).
```
