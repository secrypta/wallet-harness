# Challenge: permit2-phishing

**Vector:** permit2-phishing - Uniswap's **Permit2** is one shared contract that holds token
allowances for many dApps. After a one-time `approve(Permit2, max)`, spending rights are
granted by *off-chain signatures* over a `PermitSingle` (`spender`, `amount`, `expiration`,
`nonce`). A victim who signs a malicious Permit2 payload hands an attacker a signed
authorization to pull tokens - no gas, no second prompt.

**The contract** (`src/Challenge.sol`) is the signing policy of a wallet client. Before it
asks the user to sign a Permit2 `PermitSingle` for an interaction that needs `actionAmount`
of a token, it decides *what `amount` to authorize*. As written, it fills in the maximum
`uint160` - so whoever holds that signed permit can pull the entire balance through
`Permit2.transferFrom`.

## Your task

Fix `permit2AmountFor` so that:

1. **The drain is blocked** - the Permit2 `amount` the user signs is only as large as the
   interaction needs, so a spender cannot later pull more than that.
2. **The feature still works** - a legitimate spender can still pull up to `actionAmount`.

Keep the function **signature unchanged** (`permit2AmountFor(uint256 actionAmount)` returning
`uint160`); the grader calls it exactly like that and signs a `PermitSingle` for the amount
you return. Change only the body.

> Hint: Permit2 amounts are `uint160`. Authorize only what the interaction needs. Returning
> zero would stop the drain but also break the feature - the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve permit2-phishing
```

A hidden exploit test runs in Docker: the owner has done the one-time `approve(Permit2, max)`,
then signs a real Permit2 `PermitSingle` for the amount your policy returns, an attacker
submits it and tries to drain the full balance, and a legitimate spender pulls the agreed
amount. You pass only when the `security` and `functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
