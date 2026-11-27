# Fixture provenance

```
Fixture:      address-poisoning/b-incident/usdt-poison-victim
Vector:       address-poisoning
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       Address-poisoning drain: the attacker seeds the victim's transfer history with
              a zero-value / look-alike entry whose truncated wallet display matches a real
              counterparty; the victim later copies the look-alike from history and pays it.
Reference:    - Dec 2024 ~$50M USDT: a victim sent ~$50M USDT to a poisoned look-alike
                address copied from history. Sources: Spark research; Elliptic; Etherscan.
              - Related campaigns: May 2024 ~$68M poisoning; widespread zero-value/dust
                poisoning on USDT/USDC. Sources: Elliptic; Scam Sniffer; Etherscan.
Source code:  test/UsdtAddressPoisonIncident.t.sol + src/AddressBook.sol,
              src/VulnerableSendWallet.sol, src/MockERC20.sol (this repo's own primitives,
              reused read-only).
License:      MIT (this repo).

Minimization / honest scope:
              Pattern-level reproduction anchored to the Dec 2024 USDT incident, not a
              byte-replay of a specific tx:
              - The exact victim/attacker addresses and tx hash are not pinned here; the
                incident is cited at incident level (public sources above). The two fixture
                addresses are representative numeric literals constructed so the look-alike
                shares the truncated display (0x1A2B..9F7C) with the real counterparty while
                differing in the full address - the defining property of the vector.
              - USDT modeled as a 6-decimal ERC-20 (MockERC20); VICTIM_BALANCE/SEND_AMOUNT
                (~$50M) are representative of the cited loss.
Offline:      committed source only; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/UsdtAddressPoisonIncident.t.sol asserts the poisoning premise, then shows
              a wallet that trusts the truncated display pays the look-alike; the verdict is
              derived from the outcome (funds landed on the attacker). Expected: VULNERABLE (TP).
```
