# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/simulated-exec-safe
Vector:       malicious-calldata
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       Canonical "simulate the net effect, then commit" wallet guard - the defense
              modern wallets apply to hidden/mislabeled calldata: dry-run the transaction,
              inspect the state diff (asset/allowance changes), and refuse if the real effect
              does not match the presented intent.
Reference:    General wallet-security practice: transaction-simulation guards such as Fire,
              Blockaid, Pocket Universe, Wallet Guard; wallet advisories on pre-execution
              simulation / state-diff surfacing. No single authoritative contract to vendor.
Source code:  ./SimulatedExecutor.sol (authored reference implementation, this repo).
License:      MIT (this repo).

Honest limitation (important): malicious-calldata defense is a wallet/UX simulation pattern,
              not a drop-in third-party library, so - unlike approve-drainer/permit
              (OpenZeppelin, vendored) - there is NO canonical contract whose exact code can
              be vendored as the "real safe implementation". This fixture is a faithful
              REFERENCE IMPLEMENTATION of the canonical net-effect-simulation pattern,
              authored here. It is NOT a lightly-edited copy of the repo's toy safe wrapper:
              it performs a real dry-run-then-commit (simulate in a reverting sub-call,
              inspect the net effect, commit only if benign) and catches the (b) drainer-kit
              hidden approval WITHOUT knowing it in advance.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        test/RealSafeCalldata.t.sol runs the SAME DrainerKitModule from the (b) fixture
              through the simulated executor: the simulation surfaces the hidden allowance
              grant and reverts before committing (balance intact, no allowance), while a
              genuinely benign module simulates clean and executes. Expected: BLOCKED (TN).
```
