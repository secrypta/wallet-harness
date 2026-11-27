# Challenge: permit-phishing

**Vector:** permit-phishing - an EIP-2612 `permit` grants an allowance from an *off-chain
signature* instead of an on-chain `approve`. There is no transaction in the wallet to
inspect, so phishing UIs present it as a harmless "sign to continue". The value you sign
*is* the authorization.

**The contract** (`src/Challenge.sol`) is the signing policy of a wallet client. Before it
asks the user to sign a permit for an interaction that needs `actionAmount` of a token, it
decides *what value to put in the permit*. As written, it fills in an **unlimited** value
(`type(uint256).max`) - the "infinite approval" convenience - so a spender that later holds
that signed permit can pull the entire balance.

## Your task

Fix `permitValueFor` so that:

1. **The drain is blocked** - the value the user signs is only as large as the interaction
   needs, so a spender cannot later pull more than that.
2. **The feature still works** - a legitimate spender can still pull up to `actionAmount`.

Keep the function **signature unchanged** (`permitValueFor(uint256 actionAmount)` returning
`uint256`); the grader calls it exactly like that and signs a permit for the value you
return. Change only the body.

> Hint: think about *how much* the signed permit actually needs to authorize. Signing a
> value of zero would stop the drain but also break the feature - the grader checks both
> sides.

## Check your fix

```
ctf/ctf.sh solve permit-phishing
```

A hidden exploit test runs in Docker: the owner signs a real EIP-2612 permit for the value
your policy returns, an attacker submits the signature and tries to drain the full balance,
and a legitimate spender pulls the agreed amount. You pass only when the `security` and
`functionality` lines are both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture - it runs only offline in Docker. Never deploy it to a real network.
