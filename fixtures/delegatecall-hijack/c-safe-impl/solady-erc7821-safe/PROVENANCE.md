# Fixture provenance

```
Fixture:      delegatecall-hijack/c-safe-impl/solady-erc7821-safe
Vector:       delegatecall-hijack
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `accounts/ERC7821.sol` - a canonical ERC-7821 minimal batch-execution
              account (smart wallet). Its executor runs each batched operation with a plain
              `call` (ERC7821._execute(address,uint256,bytes,bytes32) uses
              `call(gas(), to, value, ...)`), and there is no `operation` flag to request a
              delegatecall. The delegatecall-hijack vector (Bybit/Parity: an owner-approved
              transaction whose operation is delegatecall runs attacker code in the wallet's
              own storage and rewrites its implementation/owner) has no surface here - foreign
              code invoked through this wallet always runs in the callee's own context.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/accounts/ERC7821.sol -> vendored byte-identical at
              fixtures/vendor/solady-accounts/accounts/ERC7821.sol (see fixtures/vendor/PROVENANCE.md)
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./SoladyERC7821Wallet.sol (thin wallet over the unmodified Solady ERC7821; adds a
              stored `owner` and an `_execute` auth override only - the execution primitive, the
              plain `call` that makes the hijack impossible, is Solady's unmodified code).

Why holdout: Solady is an independent implementation the wal detectors were never tuned
             against, so a clean verdict here is a genuine precision signal on unseen safe code.

Behavior:    test/RealSafeDelegatecallHijack.t.sol - the owner executes a legitimate batch
             (a token transfer) to prove `execute` works (non-vacuous); then an owner-approved
             action routed to a "takeover" probe cannot rewrite the wallet (ERC-7821 executes
             via `call`, so the write lands in the probe's own storage): the wallet's owner and
             balance are untouched. The verdict is derived from the real outcome, not hardcoded.
Offline:     committed vendored source; no fork, no live RPC. Built/run in Docker.
Honesty:     wal was NOT adjusted to make this pass. Expected: BLOCKED (TN).
```
