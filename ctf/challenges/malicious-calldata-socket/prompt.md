# Challenge: Patch the Socket Gateway call-injection drain

**Vector:** malicious-calldata - a contract that executes a caller-supplied call target and
calldata without validation. The attacker points it at a user's approved token and injects a
`transferFrom`, which runs **as the contract** and spends the user's standing approval.

**The incident** (verbatim from the fixture's `PROVENANCE.md`): *Socket Gateway arbitrary
external call injection, 2024-01-16, Ethereum, ~$3.3M from ~219-230 wallets; attack tx
`0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6` (SocketGateway
`0x3a23f943181408eac424116af7b7790c94cb97a5`).* A newly added route took the call target
(`fromToken`) and the calldata (`swapExtraData`) straight from the caller and ran
`fromToken.call(swapExtraData)`. The attacker set the target to a victim's approved token and
the calldata to `transferFrom(victim, attacker, amount)`; the only post-call check compared
the gateway's native-ETH balance delta to `amount`, so passing `amount = 0` slipped past it.

**The contract** (`src/Challenge.sol`) is that minimized route. Users have granted it standing
ERC-20 approvals. As written, `performAction` calls **any** target with **any** calldata, so
an attacker drains those approvals. A single audited route implementation (`trustedRoute`, a
public immutable) is the only call target the gateway is supposed to use.

## Your task

Fix `performAction` so that:

1. **The drain is blocked** - the gateway must not make a caller-controlled call to an
   arbitrary target (e.g. a victim's token), which is how `transferFrom` gets injected.
2. **The feature still works** - a legitimate routed action through the audited `trustedRoute`
   must still succeed.

Keep the function **signature unchanged** (`performAction(address fromToken, uint256 amount,
bytes swapExtraData)`); the grader calls it exactly like that. Change only its body.

> Hint: the root cause is an *unvalidated* call target. The native-ETH balance check is the
> wrong invariant (a zero `amount` passes it). Allow-list the call target to the audited route.
> Refusing every call would stop the drain but break legitimate routing - the grader checks both.

## Check your fix

```
ctf/ctf.sh solve malicious-calldata-socket
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction - a
> test fixture that runs only offline in Docker. Never deploy it to a real network.
