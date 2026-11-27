# Challenge: create2-metamorphic

**Vector:** create2-metamorphic - a wallet trusts a contract **by its address** and keeps
trusting it even if the *code* at that address later changes. A `CREATE2` address is
pre-computable and independent of nonce; combined with code replacement, the same address can
end up running **different code** than the vetted code you trusted. The drain: the wallet
authorizes an address holding **benign** code, the code at that address is swapped for a
**drainer**, and the still-valid authorization now points at hostile logic.

> **Honesty note (read this).** This is a *toy, offline* model, like every fixture in this
> repo - **not** a live mainnet exploit. The classic `SELFDESTRUCT` + `CREATE2`-redeploy
> trick that swapped code at an existing address is **historical** after Cancun / EIP-6780
> (2024), which restricts `SELFDESTRUCT` to the contract's creating transaction. What is still
> live in the wild is the sibling variant: deploying **unexpected / look-alike** code to a
> fresh `CREATE2` address (e.g. to dodge wallet blocklists). The defense drilled here -
> **codehash pinning** - protects *code integrity* in both cases: you trust a specific vetted
> codehash, not an address. In this challenge the code swap is **modelled** with Foundry's
> `vm.etch` cheatcode (see the gate), standing in for "the code at this address is not what you
> vetted."

**The contract** (`src/Challenge.sol`) is a wallet that lets an authorized `trustee` contract
move its tokens. `authorize` records the trustee; `pull` lets the trustee withdraw. As
written, the wallet trusts the *address* forever - so once the code at that address is
swapped for a drainer, the drainer pulls the full balance.

## Your task

This is an **[advanced]** challenge: it has **two** points to fix (unlike the single-function
intro challenges). Keep **both signatures unchanged** - `authorize(address trustee)` and
`pull(address to, uint256 amount)` - and change only their bodies.

1. **The drain is blocked** - if the code at the trusted address differs from what was vetted
   when it was authorized, `pull` must reject it.
2. **The feature still works** - an unchanged, legitimately authorized trustee must still be
   able to `pull` the agreed amount.

> Hint: `address.codehash` (the `EXTCODEHASH` of an account) is the keccak256 of its code.
> **Pin** the trustee's codehash in `authorize`, then **re-check** it in `pull`. Pinning
> nothing (or never checking) leaves the hole; refusing every pull breaks the feature - the
> grader checks both, and both bodies matter.

## Check your fix

```
ctf/ctf.sh solve create2-metamorphic
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.
