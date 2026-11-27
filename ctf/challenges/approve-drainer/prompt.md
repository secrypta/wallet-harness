# Challenge: approve-drainer

**Vector:** approve-drainer - an over-broad ERC-20 approval lets a spender pull far more
than the interaction needed.

**The contract** (`src/Challenge.sol`) is a wallet that authorizes a spender to move up to
`actionAmount` of a token on its behalf. As written, it grants an *unlimited* allowance, so
the spender can later drain the entire balance.

## Your task

Fix `authorizeSpender` so that:

1. **The drain is blocked** - an authorized spender cannot pull more than it was meant to.
2. **The feature still works** - a legitimate spender can still move up to `actionAmount`.

Keep the function **signature unchanged** (`authorizeSpender(address token, address spender,
uint256 actionAmount)`); the grader calls it exactly like that. Change only the body.

> Hint: think about *how much* allowance the interaction actually needs. Setting the
> allowance to zero would stop the drain but also break the feature - the grader checks
> both sides.

## Check your fix

```
ctf/ctf.sh solve approve-drainer
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
