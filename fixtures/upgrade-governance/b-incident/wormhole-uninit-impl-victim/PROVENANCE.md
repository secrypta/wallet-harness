# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/wormhole-uninit-impl-victim
Vector:       upgrade-governance
Tier:         b-incident (minimized real public incident)
Split:        holdout                   # authored after v0.1 freeze; wal never tuned to it
Expected:     vuln                      # ground-truth label (matches meta `label`)

Incident:     Wormhole "uninitialized proxy / implementation" bug, disclosed 2022-02-24 by
              whitehat satya0x; $10,000,000 Immunefi bounty (one of the largest on record).
Root cause:   After an earlier bugfix reverted the initialization of the UUPS IMPLEMENTATION
              contract, the implementation was left UNINITIALIZED. Anyone could call
              `initialize()` on the implementation directly, take control as a Guardian, and
              then trigger a SELFDESTRUCT via DELEGATECALL (UUPS `upgradeToAndCall` runs a
              migration by delegatecall), deleting the proxy and bricking the bridge / locking
              user funds.
Mechanism:    Uninitialized upgradeable implementation -> anyone seizes guardian control ->
              privileged upgrade path = the upgrade-governance takeover vector (distinct from a
              reinit of an already-initialized proxy, a compromised key, or a governance vote).
```

## On-chain artifacts
- **NO attack transaction exists.** This was a WHITEHAT disclosure; the bug was never exploited.
  Only the resolution is on-chain: the Wormhole team called `initialize()` on the implementation
  to set the Guardians so no one else could. There is therefore no attacker tx/address to pin,
  and this fixture is **mechanism-level** (documented by multiple independent authorities below).
- The affected contract was Wormhole's Ethereum core bridge implementation behind its proxy; the
  exact implementation address is not pinned here because no attack transaction references it.

## Independent sources (>=3 authorities; facts cross-checked on mechanism/date/bounty)
- Immunefi - "Wormhole Uninitialized Proxy Bugfix Review" (authoritative):
  https://immunefi.com/blog/bug-fix-reviews/wormhole-uninitialized-proxy-bugfix-review/
  (uninitialized UUPS implementation; initialize() -> Guardian -> selfdestruct via delegatecall;
  $10M bounty to satya0x; disclosed 2022-02-24.)
- Coinspect - "Wormhole Bridge" (Learn EVM Attacks):
  https://www.coinspect.com/learn-evm-attacks/cases/wormhole-bridge/
- r.security - "Uninitialized Proxy" (WEB3 Vulnerapedia):
  https://wiki.r.security/wiki/Uninitialized_Proxy

NOTE: This is the uninitialized-implementation BUG (whitehat, Feb 2022), NOT the separate
2022-02 Wormhole $320M signature-forgery theft. The two are distinct incidents; this fixture
reproduces only the uninitialized-implementation upgrade-governance flaw.

## What is authored here (MIT, no third-party bytecode)
`../WormholeUninitImplClone.sol` is my own minimized reproduction. The selfdestruct-via-
delegatecall consequence (unreliable to reproduce offline post-Cancun / EIP-6780) is abstracted
to its takeover precondition: an attacker initializes the uninitialized implementation, becomes
its guardian, and executes a privileged upgrade action that should have been impossible. No code
or bytecode from Wormhole is copied; sources are reference only.

## Why the harness must flag it (VULNERABLE)
`test/WormholeUninitIncident.t.sol`: the implementation contract is left uninitialized; a legit
guardian controls only the proxy. The attacker calls `initialize(attacker)` on the
implementation directly, becomes its guardian, and calls the guardian-only
`submitContractUpgrade(evil)` - seizing control the design intended to be impossible. Verdict is
derived from the real outcome -> VULNERABLE.
