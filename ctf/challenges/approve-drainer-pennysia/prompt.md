# Challenge: Patch the Pennysia Settlement arbitrary-route drain

**Incident.** Pennysia Settlement stale-approval drain, 2026-11-12 (block 26399314, attack tx
`0x2716c50e...5b732d`), ~$5,131 across 4 wallets. `executeSwap` took a "route" = a venue address
plus raw calldata and low-level-called it **from the Settlement's own context, with no
allow-listing** of the venue or the call. Users had granted the Settlement a (stale) token
approval, so an attacker crafted a route whose venue was the token and whose calldata was
`transferFrom(victim, attacker, amount)` - since the Settlement is the approved spender, the
victim's standing allowance was spent.

**Vector:** approve-drainer - an external call leverages a victim's standing approval to the
calling contract (arbitrary-callee / R11 class).

**The contract** (`src/Challenge.sol`) is the minimized Settlement. `executeSwap` forwards an
attacker-chosen `(venue, route)` as a low-level call. An allow-list of venues
(`allowedVenue` / `allowVenue`) is already provided for you - but `executeSwap` does not consult
it.

## Your task

Fix `executeSwap` so that:

1. **The drain is blocked** - a route pointed at an arbitrary address (e.g. the token itself, to
   call `transferFrom` on a victim's standing approval) cannot be executed.
2. **The feature still works** - routing a swap through a legitimate, allow-listed venue still
   executes.

Keep the function **signature unchanged** (`executeSwap(address venue, bytes route)`); the grader
calls it exactly like that. Change only the body. Use the provided `allowedVenue` mapping.

> Hint: the Settlement must not call just any address with its own authority. Only route to
> venues that were explicitly allow-listed. Rejecting every route would stop the drain but also
> break legitimate swaps - the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve approve-drainer-pennysia
```

A hidden exploit test runs in Docker: an attacker routes a `transferFrom` against a victim's
standing approval, while a legitimate swap is routed through an allow-listed venue. You pass only
when the `security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction of a real
> incident for training - it runs only offline in Docker. Never deploy it to a real network.
