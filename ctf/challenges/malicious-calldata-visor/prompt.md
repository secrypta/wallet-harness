# Challenge: Patch the Visor Finance delegated-transfer drain

**Vector:** malicious-calldata (caller-supplied-callee shape) - a contract trusts a
**caller-supplied** helper contract to pull a deposit and to report who to credit, without
verifying that any real transfer happened.

**The incident** (verbatim from the fixture's `PROVENANCE.md`): *Visor Finance (VISR) exploit,
2021-12-21, Ethereum, ~$8.2M (8,812,958 VISR); attack tx
`0x69272d8c84d67d1da2f6425b339192fa472898dce936f24818fda415c1c1ff3f` (RewardsHypervisor
`0xc9f27a50f82571c1c8423a42970613b8dbda14ef`).* The vVISR rewards hypervisor's `deposit`
called `visor.delegatedTransferERC20(...)` on a caller-chosen `visor` contract to pull the
deposit, and credited shares to `visor.owner()`. The attacker passed their own contract whose
transfer was a **no-op** and whose `owner()` returned the attacker - so the hypervisor minted
shares for a deposit that never happened, and the attacker withdrew real pooled VISR.

**The contract** (`src/Challenge.sol`) is that minimized hypervisor. `seed` is a normal
deposit; `deposit(amount, visor)` is the vulnerable path; `withdraw` redeems shares for real
VISR. As written, `deposit` trusts the caller-supplied `visor` for both the pull and the
credited owner, verifying nothing.

## Your task

Fix `deposit` so that:

1. **The drain is blocked** - shares may be credited only for VISR the hypervisor *actually*
   received, and only to the real depositor - a no-op transfer must mint nothing.
2. **The feature still works** - a genuine deposit (the helper really transfers `amount`) must
   still credit `amount` shares that can be withdrawn.

Keep the function **signature unchanged** (`deposit(uint256 amount, address visor)`); the
grader calls it exactly like that. Change only its body.

> Hint: don't trust a self-report. Measure the hypervisor's VISR balance before and after the
> pull and require it actually rose by `amount`, and credit the caller (`msg.sender`), not the
> helper's self-reported `owner()`. (The post-mortem's fix was to use a fixed
> `ERC20.transferFrom` instead of the caller-supplied transfer - either way, verify the real
> movement.) Crediting nothing would stop the theft but break real deposits - the grader
> checks both.

## Check your fix

```
ctf/ctf.sh solve malicious-calldata-visor
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction - a
> test fixture that runs only offline in Docker. Never deploy it to a real network.
