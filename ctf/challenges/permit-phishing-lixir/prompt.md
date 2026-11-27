# Challenge: Patch the Lixir forged-permit drain

**Incident.** Lixir vault-token forged-permit approval drain, 2026-06-25 (Ethereum), attack tx
`0x17026fac...0a41da` (block 25391316). Per the public post-mortem, the vault token's EIP-2612
`permit` "accepted a dummy signature as long as `ecrecover` returned a nonzero address" - it
checked only that the recovered signer was **non-zero**, never that it equalled `owner`. An
attacker forged a signature, was granted an allowance, and `transferFrom`'d holders' balances.
One non-owner signature was reused across 41 `permit` calls over 35 owners.

**Vector:** permit-phishing - an EIP-2612 `permit` grants an allowance from an off-chain
signature. Here the token's own signature check is broken, so no real owner signature is even
needed.

**The contract** (`src/Challenge.sol`) is the minimized vault token. Its `permit` sets the
allowance whenever `ecrecover(...)` is merely non-zero - the documented bug.

## Your task

Fix `permit` so that:

1. **The drain is blocked** - a forged signature that does not come from `owner` is rejected,
   so no allowance is granted and the holder cannot be drained.
2. **The feature still works** - a genuine permit, signed by the real `owner`, still sets the
   allowance so a legitimate spender can pull the agreed amount.

Keep the function **signature unchanged** (`permit(address owner, address spender, uint256
value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)`); the grader calls it exactly like
that. Change only the body.

> Hint: the recovered signer must be the one thing the broken check forgot to compare it to.
> Rejecting every signature would stop the drain but also break genuine permits - the grader
> checks both sides.

## Check your fix

```
ctf/ctf.sh solve permit-phishing-lixir
```

A hidden exploit test runs in Docker: an attacker forges a signature that is not the owner's
and tries to drain the holder, while separately the real owner signs a genuine permit that a
legitimate spender consumes. You pass only when the `security` and `functionality` lines are
both OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction of a
> real incident for training - it runs only offline in Docker. Never deploy it to a real network.
