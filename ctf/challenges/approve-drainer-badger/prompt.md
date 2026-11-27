# Challenge: Patch the BadgerDAO approval-injection drain

**Incident.** BadgerDAO front-end compromise, 2021-12-02. A compromised front-end injected
`increaseAllowance(attacker, ...)` calls into victim wallets; the attacker then `transferFrom`'d
the balances out. The largest single-victim drain (tx `0x951babdd...029869`) moved ~900 byvWBTC
(~$50.8M); the full incident drained ~$120M across 500+ approvers through the same path.

**Vector:** approve-drainer - an over-broad ERC-20 allowance lets a spender pull far more than
the interaction needed.

**The contract** (`src/Challenge.sol`) is the wallet's approval helper. To let `spender` move up
to `actionAmount` for one interaction, it bumps the allowance - but, as written, it grants an
*unlimited* allowance (exactly the unbounded `increaseAllowance` the compromised Badger
front-end induced), so the spender can later drain the entire balance.

## Your task

Fix `authorizeSpender` so that:

1. **The drain is blocked** - an authorized spender cannot pull more than it was meant to.
2. **The feature still works** - a legitimate spender can still move up to `actionAmount`.

Keep the function **signature unchanged** (`authorizeSpender(address token, address spender,
uint256 actionAmount)`); the grader calls it exactly like that. Change only the body.

> Hint: grant only the allowance the interaction actually needs. Granting zero would stop the
> drain but also break the feature - the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve approve-drainer-badger
```

A hidden exploit test runs in Docker: it authorizes a spender for the action amount, then an
attacker tries to pull the full balance, while a legitimate spender pulls the agreed amount. You
pass only when the `security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction of a real
> incident for training - it runs only offline in Docker. Never deploy it to a real network.
