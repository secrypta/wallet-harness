# Challenge: Patch the Parity wallet-library drain

**Vector:** delegatecall-hijack - a wallet that `delegatecall`s a shared library runs that
library's code in its own storage. If a state-changing library function can be reached again
on a live wallet, an attacker runs it as the wallet and seizes it.

**The incident** (verbatim from the fixture's `PROVENANCE.md`): *Parity multisig wallet
(first Parity hack), 2017-07-19; ~153,037 ETH (~$30M) across affected wallets (82,189.93 ETH
from the example wallet); attack tx `0x9dbf0326a03a2a3719c27be4fa69aacc9857fd231a8d9dcaede4bb083def75ec`.*
Each Parity multisig was a thin proxy that `delegatecall`ed one shared wallet library. The
library's `initWallet` (ownership setup) had **no "already initialized" guard** and was
reachable through the proxy's delegatecall fallback - so anyone could re-initialize a live,
funded wallet's owner to themselves and then `execute` a transfer of its whole balance.

**The contract** (`src/Challenge.sol`) is that shared library. It runs in the proxy's storage
via delegatecall (its `owner` aligns with the proxy's slot 0). As written, `initWallet` sets
the owner **every time it is called**.

## Your task

Fix `initWallet` so that:

1. **The drain is blocked** - ownership can be set only ONCE; a second `initWallet` on an
   already-initialized wallet must not re-assign the owner.
2. **The feature still works** - the first, legitimate `initWallet` must still set the owner,
   and that owner can still `execute` a transfer.

Keep the function **signature unchanged** (`initWallet(address newOwner)`); the grader calls
it exactly like that. Change only its body. (`execute` is not part of the puzzle - leave it.)

> Hint: the historical fix was an "already initialized" guard. A `bool initialized` storage
> slot is declared for you. Refusing to ever set an owner would stop the takeover but break
> the wallet's first setup - the grader checks both.

## Check your fix

```
ctf/ctf.sh solve delegatecall-hijack-parity
```

A hidden exploit test runs in Docker and reports a `GATE` verdict with a `security` and a
`functionality` line. You pass only when both are OK.

---
> **Toy challenge.** This contract is a deliberately vulnerable, minimized reproduction - a
> test fixture that runs only offline in Docker. Never deploy it to a real network.
