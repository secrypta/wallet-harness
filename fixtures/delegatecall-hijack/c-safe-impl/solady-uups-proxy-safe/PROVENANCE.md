# Fixture provenance

```
Fixture:      delegatecall-hijack/c-safe-impl/solady-uups-proxy-safe
Vector:       delegatecall-hijack
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       Solady `utils/UUPSUpgradeable.sol` - an independent (non-OpenZeppelin) UUPS proxy
              mixin. Like any proxy it USES delegatecall, but only to the implementation in the
              ERC-1967 implementation slot. The delegatecall-hijack vector (Parity/Bybit) is an
              owner-approved operation delegatecalling a CALLER-CHOSEN target; this wallet has
              no such sink: the only delegatecall target is the managed slot, changing it
              (`upgradeToAndCall`) is gated by `_authorizeUpgrade` (owner), and owner operations
              run via `execute` with a plain `call` (no delegatecall operation mode). PRECISION
              fixture: an independent proxy's delegatecall-to-implementation must NOT be flagged.
Source:       https://github.com/Vectorized/solady  tag v0.1.22
              commit 65e87c72a5ee4a6708946b25611ec5f980ceba70
              file src/utils/UUPSUpgradeable.sol (+ utils/CallContextChecker.sol) -> vendored
                   byte-identical under fixtures/vendor/solady-accounts/ (see
                   fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2022-2025 Solady; full text in fixtures/vendor/solady/LICENSE.
Source code:  ./SoladyUUPSWallet.sol (thin wallet over the unmodified Solady UUPSUpgradeable: a
              stored `owner`, owner-gated `_authorizeUpgrade`, and an owner-only `execute` that
              uses a plain `call`; changes none of Solady's upgrade logic.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The claim it encodes (a UUPS proxy
delegatecalls only its managed implementation slot, upgrade-gated) is the documented behaviour
of the Solady UUPS mixin and EIP-1822/EIP-1967:
- Solady source header (self-documenting): intended for use with ERC-1967 proxies.
- EIP-1822 / UUPS (`proxiableUUID`, `_authorizeUpgrade`): https://eips.ethereum.org/EIPS/eip-1822
- EIP-1967 (proxy storage slots): https://eips.ethereum.org/EIPS/eip-1967

## Distinct from the other delegatecall-hijack safe fixtures
`oz-erc1967-proxy-safe` (round 4) is OpenZeppelin's ERC1967/UUPS; `solady-erc7821-safe` is a
call-based batch executor. This fixture is Solady's INDEPENDENT UUPS implementation behind an
ERC-1967 proxy - a different codebase's proxy mechanism.

## Why the harness must stay silent (BLOCKED)
The test deploys the wallet behind a real `ERC1967Proxy`, proves a legit owner op works
(non-vacuous), has an unauthorized key try `upgradeToAndCall(evil)` to redirect the
delegatecall sink (reverts), and has the owner route an op to a storage-takeover probe (runs
via plain `call` in its own context). The wallet's owner/implementation/balance are untouched
-> verdict BLOCKED, 0 false positives.
