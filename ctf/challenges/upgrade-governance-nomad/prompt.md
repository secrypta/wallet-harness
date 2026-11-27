# Challenge: Patch the Nomad Bridge re-init drain

**Vector:** upgrade-governance - a routine implementation upgrade re-ran an initializer that
corrupted trusted state, turning an authorization check into a no-op.

**The incident** (verbatim from the fixture's `PROVENANCE.md`): *Nomad Bridge exploit,
2022-08-01, Ethereum, ~$190M drained; drain tx
`0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460` (Nomad Replica proxy
`0x5d94309e5a0090b165fa4181519701637b6daeba`).* A Replica upgrade re-ran `initialize()`,
which marked the **zero root** as an acceptable ("proven") root. Any message whose Merkle
proof was never run resolves to the zero root - so every forged message then passed the root
check, and anyone could submit a fabricated message and withdraw custodied funds.

**The contract** (`src/Challenge.sol`) is that minimized Replica. `confirmRoot` lets
governance mark a genuinely proven (non-zero) root acceptable; `process` releases funds for a
message whose root is acceptable. The upgrade's `initialize()` has already run here and left
the zero root acceptable - so as written, `process` honors a forged message that resolves to
the zero root.

## Your task

Fix `process` so that:

1. **The drain is blocked** - a message that resolves to the zero root (an un-proven / forged
   message) must be rejected, even though `initialize` left the zero root "acceptable".
2. **The feature still works** - a legitimately proven, non-zero root must still process and
   release the agreed amount.

Keep the function **signature unchanged** (`process(bytes32 provenRoot, address to, uint256
amount)`); the grader calls it exactly like that. Change only its body. (`initialize` models
the incident's buggy upgrade - leave it; fix the authorization at the point funds leave.)

> Hint: a never-proven message resolves to `bytes32(0)`. A real proof never resolves to the
> zero root. Rejecting every message would stop the drain but break legitimate bridging - the
> grader checks both.

## Check your fix

```
ctf/ctf.sh solve upgrade-governance-nomad
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction - a
> test fixture that runs only offline in Docker. Never deploy it to a real network.
