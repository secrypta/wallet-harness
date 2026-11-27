# Fixture provenance

```
Fixture:      delegatecall-hijack/c-safe-impl/oz-erc1967-proxy-safe
Vector:       delegatecall-hijack
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `proxy/ERC1967/ERC1967Proxy.sol` + `proxy/utils/UUPSUpgradeable.sol`
              - the canonical ERC-1967 / UUPS upgradeable-proxy pair. A proxy's core mechanism
              IS delegatecall: `Proxy._delegate` forwards every call to the implementation
              recorded in the ERC-1967 implementation slot (`ERC1967Utils.getImplementation()`).
              The delegatecall-hijack vector (Parity/Bybit) is not "uses delegatecall" but
              "an owner-approved operation delegatecalls a CALLER-CHOSEN target, so attacker
              code runs in the wallet's storage and rewrites owner/implementation". This proxy
              has no such sink: the only delegatecall target is the MANAGED implementation slot
              (never caller input), changing it (`upgradeToAndCall`) is gated by UUPS
              `_authorizeUpgrade`, and owner operations run through `execute` which uses a
              plain `call` (no delegatecall operation mode). PRECISION fixture: a real proxy's
              delegatecall-to-implementation must NOT be flagged.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files proxy/ERC1967/ERC1967Proxy.sol, proxy/ERC1967/ERC1967Utils.sol,
                    proxy/Proxy.sol, proxy/utils/UUPSUpgradeable.sol,
                    proxy/utils/Initializable.sol (+ import closure) -> vendored byte-identical
                    under fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZERC1967ProxyWallet.sol (thin UUPS wallet over the unmodified OZ base: a
              stored `owner`, owner-gated `_authorizeUpgrade`, and an owner-only `execute` that
              uses a plain `call`; a V2 proves a legit upgrade still applies. Changes none of
              OZ's proxy/upgrade logic.)
```

## Independent corroboration (the pattern, not an incident)
This is a safe-side PRECISION fixture, so there is no incident to triangulate. The claim it
encodes - that an ERC-1967/UUPS proxy's delegatecall targets only its managed implementation
slot, upgrade-gated, with no caller-chosen delegatecall sink - is the documented behaviour of:
- OpenZeppelin Proxy docs: https://docs.openzeppelin.com/contracts/5.x/api/proxy
- EIP-1967 (standard proxy storage slots): https://eips.ethereum.org/EIPS/eip-1967
- EIP-1822 / UUPS (`proxiableUUID`, `_authorizeUpgrade`): https://eips.ethereum.org/EIPS/eip-1822

## Why the harness must stay silent (BLOCKED)
The test (`test/RealSafeDelegatecallHijack.t.sol`) deploys the wallet behind a real
`ERC1967Proxy`, proves legit owner operations and a legit owner upgrade work (non-vacuous),
then (a) has an unauthorized key try `upgradeToAndCall(evil)` to redirect the delegatecall
sink - it reverts; and (b) has the owner route an operation to a storage-takeover probe - it
runs via plain `call` in its own context, leaving the wallet's owner/implementation/balance
untouched. No delegatecall takeover is possible -> verdict BLOCKED, 0 false positives.
