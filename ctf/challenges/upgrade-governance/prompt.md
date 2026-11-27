# Challenge: upgrade-governance

**Vector:** upgrade-governance - an upgradeable wallet routes its asset-moving logic through
a swappable `implementation`. If a single owner key can replace that implementation
**instantly** (no delay, no guardian), then whoever holds (or steals) that one key can swap
in hostile logic and empty the wallet in the same breath. One compromised key == instant
malicious upgrade == full drain.

**The contract** (`src/Challenge.sol`) delegatecalls its `implementation` to run operations.
`setImplementation` is how the implementation is changed. As written, it applies the new
implementation **immediately**, so a compromised owner can point the wallet at a hostile
implementation and drain it at once.

## Your task

Fix `setImplementation` so that:

1. **The drain is blocked** - a newly requested implementation must **not** become active in
   the same transaction it is requested; an instant single-key swap-and-drain is impossible.
2. **The feature still works** - a *legitimate* upgrade must still take effect after the
   mandated delay (`DELAY`, a public immutable), and the wallet keeps operating through the
   new implementation.

Keep the function **signature unchanged** (`setImplementation(address newImpl)`); the grader
calls it exactly like that. Change only the body (and the storage you need - `pendingImpl`
and `pendingEta` are already declared for you).

> Hint: make it a two-step, same-signature timelock. The first call to
> `setImplementation(x)` *schedules* `x` (records it and an eta `now + DELAY`); a later call
> to `setImplementation(x)`, once the eta has passed, *applies* it. Never applying anything
> would stop the drain but break legitimate upgrades - the grader checks both. (A production
> wallet would add a guardian that can cancel a pending upgrade during the window; the gate
> checks the delay.)

## Check your fix

```
ctf/ctf.sh solve upgrade-governance
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
