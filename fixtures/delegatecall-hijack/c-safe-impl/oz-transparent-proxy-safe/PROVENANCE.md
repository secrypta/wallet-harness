# Fixture provenance

```
Fixture:      delegatecall-hijack/c-safe-impl/oz-transparent-proxy-safe
Vector:       delegatecall-hijack
Tier:         c-safe-impl (genuinely-safe real code)
Split:        holdout                   # independent real code; wal never tuned to it
Expected:     safe                      # ground-truth label (matches meta `label`)

Origin:       OpenZeppelin `proxy/transparent/TransparentUpgradeableProxy.sol` + `ProxyAdmin.sol`
              - the canonical transparent-proxy pattern. The proxy USES delegatecall (every
              non-admin call is forwarded to the ERC-1967 implementation) and upgrades are
              routed through a dedicated `ProxyAdmin` owned by the governance owner: only the
              admin may call the proxy's `upgradeToAndCall`, any other caller is delegatecalled
              to the implementation. The delegatecall-hijack vector (Parity/Bybit) is an
              owner-approved op delegatecalling a CALLER-CHOSEN target; this proxy has no such
              sink (the only delegatecall target is the managed slot; it cannot be redirected
              except by the ProxyAdmin owner). PRECISION fixture.
Source:       https://github.com/OpenZeppelin/openzeppelin-contracts  tag v5.1.0
              commit 69c8def5f222ff96f2b5beff05dfba996368aa79
              files proxy/transparent/TransparentUpgradeableProxy.sol,
                    proxy/transparent/ProxyAdmin.sol (+ ERC1967Proxy, ERC1967Utils, IERC1967,
                    access/Ownable import closure) -> vendored byte-identical under
                    fixtures/vendor/oz/ (see fixtures/vendor/PROVENANCE.md).
License:      MIT - Copyright (c) 2016-2024 Zeppelin Group Ltd; full text in
              fixtures/vendor/oz/LICENSE.
Source code:  ./OZTransparentProxyWallet.sol (thin logic over the unmodified OZ transparent
              proxy: a stored `owner` and an owner-only `execute` via plain `call`; a V2 proves
              a legit admin-routed upgrade still applies. Changes none of OZ's proxy logic.)
```

## Independent corroboration (the pattern, not an incident)
Safe-side PRECISION fixture - no incident to triangulate. The admin/user call-routing and
ProxyAdmin-gated upgrade are the documented behaviour of the transparent-proxy pattern:
- OZ Proxy docs (transparent vs UUPS): https://docs.openzeppelin.com/contracts/5.x/api/proxy
- EIP-1967 (admin + implementation slots): https://eips.ethereum.org/EIPS/eip-1967

## Distinct from the other delegatecall-hijack safe fixtures
`oz-erc1967-proxy-safe` is a bare ERC1967/UUPS proxy; `solady-uups-proxy-safe` is Solady's UUPS;
`solady-erc7821-safe` is a call-based executor. This fixture is the TRANSPARENT-proxy admin
pattern (external ProxyAdmin, admin/user call-routing) - a different real proxy mechanism.

## Why the harness must stay silent (BLOCKED)
The test deploys the logic behind a real `TransparentUpgradeableProxy` (with a `ProxyAdmin`
owned by the governance owner), proves a legit owner op works, has an unauthorized key try to
upgrade both via the proxy directly (delegatecalled to the logic, which has no such function,
reverts) and via the ProxyAdmin (`onlyOwner`, reverts), and routes an owner op to a
storage-takeover probe (plain `call`, own context). A legit admin-routed upgrade to V2 then
applies (non-vacuous). The wallet is never hijacked -> verdict BLOCKED, 0 false positives.
