# Challenge: Patch the Anyswap permit-bypass drain

**Incident.** Anyswap/Multichain AnyswapV4Router permit-validation bypass, 2022-01-19
(Ethereum), attack tx `0xe50ed602...6227f7` (block 14037237), ~976.86 WETH stolen. The router's
`anySwapOutUnderlyingWithPermit` forwarded a `permit(...)` to the underlying token and only
required that the call **did not revert** - it never checked that a valid signature actually
granted an allowance. WETH has no `permit`, so the call hit WETH's permissive fallback and
succeeded without verifying anything; the router then `transferFrom`'d the underlying using the
victim's **pre-existing standing approval** to the router. Anyone could drain any address that
had approved the router.

**Vector:** permit-phishing - an allowance is (supposedly) authorized by an off-chain signature.
Here the router trusts a permit that never happened.

**The contract** (`src/Challenge.sol`) is the minimized router. Its
`anySwapOutUnderlyingWithPermit` forwards the permit and immediately pulls `amount` - trusting
that the permit granted it.

## Your task

Fix `anySwapOutUnderlyingWithPermit` so that:

1. **The drain is blocked** - a token whose `permit` did not actually grant a fresh allowance
   for this call (e.g. WETH's no-op fallback, leaving only a pre-existing standing approval)
   cannot be pulled.
2. **The feature still works** - when the owner provides a genuine permit on a token that
   implements it, the router still pulls up to `amount`.

Keep the function **signature unchanged** (`anySwapOutUnderlyingWithPermit(address owner, address
token, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s)`); the grader calls it
exactly like that. Change only the body.

> Hint: don't trust that `permit` "didn't revert". Verify that it actually granted the allowance
> this call needs - a real permit leaves `allowance(owner, router) == amount`, a no-op fallback
> does not. Pulling nothing would be safe but break the feature - the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve permit-phishing-anyswap
```

A hidden exploit test runs in Docker: an attacker invokes the router against a WETH-like token
(no permit, permissive fallback) that a victim had a standing approval on, while separately a
genuine owner-signed permit on a proper token is routed legitimately. You pass only when the
`security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction of a
> real incident for training - it runs only offline in Docker. Never deploy it to a real network.
