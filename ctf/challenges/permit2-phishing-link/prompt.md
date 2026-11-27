# Challenge: Patch the LINK Permit2 phishing drain

**Incident.** LINK Permit2 phishing drain, drain tx `0xa25807c8...339b04d0` (Ethereum, block
26113853, 2026-10-03). The victim had a standing `approve(Permit2, max)` on LINK - reported
~411 days old - and was phished into signing a single off-chain Uniswap Permit2 `PermitSingle`
naming the attacker as spender with an **unbounded** amount. The attacker submitted the
signature and swept the entire balance (12,041.30 LINK) in one `transferFrom`.

**Vector:** permit2-phishing - one shared Permit2 contract holds allowances for many dApps.
After the one-time `approve(Permit2, max)`, spending rights are granted by off-chain
`PermitSingle` signatures. The amount you sign *is* the authorization.

**The contract** (`src/Challenge.sol`) is the signing policy of a wallet client. Before it asks
the user to sign a `PermitSingle` for an interaction that needs `actionAmount`, it decides the
Permit2 `amount` to authorize. As written, it signs the maximum `uint160` - exactly the
unbounded signature the victim was phished into.

## Your task

Fix `permit2AmountFor` so that:

1. **The drain is blocked** - the Permit2 `amount` the user signs is only as large as the
   interaction needs, so a later full-balance `transferFrom` cannot pull more than that.
2. **The feature still works** - a legitimate spender can still pull up to `actionAmount`.

Keep the function **signature unchanged** (`permit2AmountFor(uint256 actionAmount)` returning
`uint160`); the grader calls it exactly like that and signs a `PermitSingle` for the amount you
return. Change only the body.

> Hint: Permit2 amounts are `uint160`. Authorize only what the interaction needs. Returning zero
> would stop the drain but also break the feature - the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve permit2-phishing-link
```

A hidden exploit test runs in Docker: the owner has done the one-time `approve(Permit2, max)`,
signs a `PermitSingle` for the amount your policy returns, an attacker submits it and tries to
drain the full balance, and a legitimate spender pulls the agreed amount. You pass only when the
`security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract and its Permit2 model are a deliberately minimized
> reproduction of a real incident for training - they run only offline in Docker. Never deploy
> them to a real network.
