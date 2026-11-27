# Fixture provenance

```
Fixture:      address-poisoning/c-safe-impl/verified-send-safe
Vector:       address-poisoning
Tier:         c-safe-impl
Expected:     safe                     # ground-truth label (matches meta `label`)

Origin:       Canonical full-address-verification send policy (the defense real wallets use
              against address poisoning): resolve the recipient by the FULL address of a
              counterparty the user has explicitly verified, never by the truncated display.
Reference:    General wallet security practice / address-poisoning guidance (e.g. MetaMask,
              Etherscan, Trezor/Ledger advisories on verifying the full address, not a
              displayed prefix/suffix). No single authoritative contract to cite.
Source code:  ./VerifiedSendPolicy.sol (authored reference implementation, this repo)
License:      MIT (this repo).

Honest limitation (important): address-poisoning is a UX / transaction-history attack, not
              a contract bug, so - unlike approve-drainer/permit (OpenZeppelin) - there is NO
              third-party library whose exact code can be vendored as the "real safe
              implementation". This fixture is therefore a faithful REFERENCE IMPLEMENTATION
              of the canonical pattern, authored here, NOT vendored third-party code. It is
              not a lightly-edited copy of this repo's toy wrapper either: it is the standard
              full-address-verify policy, with the verification logic as the point.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        test/RealSafeAddressPoisoning.t.sol first asserts the poisoning premise (the
              look-alike shares the truncated display with a verified counterparty but
              differs in full address), then shows a send to the look-alike reverts under
              full-address verification (funds retained) while a genuine send to the verified
              counterparty succeeds. Expected verdict: BLOCKED (TN).
```
