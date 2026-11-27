# Fixture provenance

```
Fixture:      malicious-calldata/c-safe-impl/solady-erc4337-executor-safe
Vector:       malicious-calldata
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `accounts/ERC4337.sol` - a canonical, widely-used ERC-4337 smart-account
              base. Its `execute(target, value, payload)` / `executeBatch(Call[])` perform a
              low-level call to ANY target with ANY payload - exactly the arbitrary-external
              -call shape the malicious-calldata vector abuses (Socket 2024 / LI.FI 2024 /
              Rubic 2022: a contract runs a caller-supplied target + calldata against a
              victim's standing approval). It is safe not because the sink is absent but
              because reaching it is GATED by `onlyEntryPointOrOwner`: the caller must be the
              canonical ERC-4337 EntryPoint (which only forwards an owner-signed, validated
              UserOperation) or the account owner. An attacker who is neither cannot inject
              `transferFrom(victim, attacker, ...)` nor sweep the account; the call reverts
              `Unauthorized()`.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/accounts/ERC4337.sol (+ ERC4337Factory.sol and their import closure) ->
                   vendored BYTE-IDENTICAL, upstream layout, under
                   fixtures/vendor/solady-accounts/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in
              fixtures/vendor/solady/LICENSE.
Source code:  ./SoladyErc4337Executor.sol (in c-safe-impl/) authors NO logic - it is the stock
              Solady ERC4337 with ONLY the required `_domainNameAndVersion` override, so the
              fixture has a concrete, deployable subject. The test drives the real contract,
              deployed via the canonical vendored `ERC4337Factory`.
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The `onlyEntryPointOrOwner` gating of
the account's arbitrary-call executor is the documented ERC-4337 account-abstraction model:
- ERC-4337 spec (EntryPoint-mediated execution): https://eips.ethereum.org/EIPS/eip-4337
- Solady account docs / source: https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol

## Distinct from the other malicious-calldata c-safe fixtures
- oz-multicall-safe: self-atomic batch of the contract's OWN calls (msg.sender preserved) - no
  external arbitrary target.
- oz-timelock-executor-safe: role (EXECUTOR_ROLE) + prior schedule + elapsed min-delay.
- solady-multicallable-safe: self-delegatecall batch, no external target.
- solady-ownableroles-executor-safe: OwnableRoles role check.
- simulated-exec-safe: a simulate/execute split.
Here the gate is the ERC-4337 ACCOUNT-ABSTRACTION model (caller is the EntryPoint, which
forwarded a signed+validated userOp, or the owner) - a different real mechanism.

## Distinct from the signature-phishing ERC-4337 holdout
`signature-phishing/c-safe-impl/solady-erc4337-userop-safe` exercises userOp SIGNATURE
VALIDATION (`_validateSignature`: a forged-signature userOp fails, EntryPoint never runs it).
Here the attack is arbitrary-external-call INJECTION: an attacker directly calls `execute(...)`
to drain, and the `onlyEntryPointOrOwner` gate reverts it. Same base contract, different
vector, different exploited/blocked surface - consistent with corpus practice (e.g. OZ
TimelockController appears as both a gated executor and an upgrade authority).

## Why the harness must stay silent (BLOCKED)
The test deploys a real Solady ERC4337 account (owner via the vendored factory), funds it, then
has an unauthorized attacker try to drain it via `execute(token, 0, transfer(attacker, all))`
(reverts `Unauthorized()`). The account keeps its balance. Non-vacuous: the account OWNER
legitimately executes a benign `execute(...)` that moves funds, so the executor is live, not
dead. Verdict BLOCKED.

If a (future) static malicious-calldata detector flagged this as VULNERABLE, that would be a
genuine detector false positive on a gated arbitrary-call executor - to be recorded as a
finding, NOT masked by altering this fixture.
