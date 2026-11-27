# Challenge: Patch the Magic Eden Payment Processor forwarder spoof

**Vector:** set-approval-for-all - real incident. On **2026-09-24** Limit Break's "Payment
Processor V2" (used by Magic Eden) was drained (**~$2.8M**: ~622 WETH + NFTs across several
chains). Many wallets still held a standing `setApprovalForAll(processor, true)` from 2024
listings. The processor accepted **meta-transactions** through an **ERC-2771 trusted
forwarder** and trusted the sender address the forwarder appended to the calldata - but the
forwarder **never authenticated** that the caller was actually that sender. So anyone could
route a call through the trusted forwarder claiming to be a **victim**, and the processor,
believing the victim had acted, pulled the victim's NFTs with their lingering operator
approval. (Example tx `0x9050e2...93d3`, block 26047513.)

**The contract** (`src/Challenge.sol`) is that **trusted forwarder**. `forward` relays `data`
to `target`, appending `from` as the ERC-2771 sender the target will trust. As written it
lets **any caller claim any `from`** - so an attacker forwards a trade "as the victim" and the
processor settles it against the victim's NFTs.

## Your task

Fix `forward` so that:

1. **The drain is blocked** - a caller cannot relay a meta-transaction claiming to be someone
   else.
2. **The feature still works** - a user can still relay their *own* meta-transaction through
   the forwarder (the legitimate gasless-listing flow).

Keep the function **signature unchanged** (`forward(address target, bytes data, address
from)`); the grader calls it exactly like that. Change only the body.

> Hint: the target trusts whatever sender this forwarder appends, so the forwarder must prove
> the caller really is `from` before appending it. Refusing to forward at all would stop the
> drain but also break the legitimate relay; the grader checks both sides.

## Check your fix

```
ctf/ctf.sh solve set-approval-for-all-magic-eden
```

A hidden exploit test runs in Docker and reports a `security` and a `functionality` line.
You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable test fixture modeled on a
> public incident - it runs only offline in Docker. Never deploy it to a real network.
