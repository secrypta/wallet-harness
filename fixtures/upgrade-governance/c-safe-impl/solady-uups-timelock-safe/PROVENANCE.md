# Fixture provenance

```
Fixture:      upgrade-governance/c-safe-impl/solady-uups-timelock-safe
Vector:       upgrade-governance
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `utils/UUPSUpgradeable.sol` (+ `CallContextChecker`, `LibClone`'s ERC-1967
              proxy) as the UUPS upgrade machinery, with a real OpenZeppelin v5.1.0
              `TimelockController` as the upgrade authority. This is the independent-codebase
              sibling of the existing `oz-timelock-safe` fixture: the safe property - an instant,
              single-key implementation swap is impossible because the authority is a delay- and
              role-gated timelock - is demonstrated on Solady's UUPS instead of OpenZeppelin's.
Source:       Solady:  https://github.com/Vectorized/solady  tag v0.1.22
                       commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
                       files src/utils/{UUPSUpgradeable,CallContextChecker,LibClone}.sol
                       -> vendored byte-identical under fixtures/vendor/solady-accounts/utils/
              OpenZeppelin: https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
                       commit 69c8def5f222ff96f2b5beff05dfba996368aa79
                       file governance/TimelockController.sol
                       -> vendored byte-identical under fixtures/vendor/oz/
              (see fixtures/vendor/PROVENANCE.md for both closures).
License:      Solady MIT (Copyright (c) 2022-2025 Solady; fixtures/vendor/solady/LICENSE);
              OpenZeppelin MIT (Copyright (c) 2016-2024 Zeppelin Group Ltd; fixtures/vendor/oz/LICENSE).
Source code:  ./SoladyTimelockUUPSWallet.sol (thin wallet over the unmodified Solady UUPS: a
              one-shot initializer + the `_authorizeUpgrade` override gating on the timelock;
              no bespoke delay logic - the delay guarantee is the real OZ TimelockController).

Why holdout: Solady UUPS is a DIFFERENT, independent implementation the wal detectors were never
             tuned against, so a clean verdict here is a genuine precision signal on unseen safe
             code.

Behavior:    test/RealSafeUpgradeGovernanceSolady.t.sol - a compromised single key's direct
             `upgradeToAndCall` to a draining implementation reverts in `_authorizeUpgrade`
             (caller is not the timelock), so the wallet is never emptied; and a legitimate
             upgrade scheduled through the TimelockController applies only after the min-delay
             (so BLOCKED is not vacuous). Verdict derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN).
```
