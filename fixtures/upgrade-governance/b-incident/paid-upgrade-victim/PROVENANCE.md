# Fixture provenance

```
Fixture:      upgrade-governance/b-incident/paid-upgrade-victim
Vector:       upgrade-governance
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Proof level:  incident-level           # named public incident + multiple post-mortems documenting
                                        # the exact unguarded-upgrade mechanism; NO upgrade/mint tx
                                        # hash is cited (not pinned in the verified public write-ups;
                                        # recovering it would need live chain history, avoided by policy).

Origin:       PAID Network token exploit, 2021-03-05. An upgradeable (proxy) ERC-20 whose
              implementation could be replaced by a SINGLE key (the original deployer's). That
              key was compromised; the attacker swapped in an implementation - absent from the
              audited code - that could burn and re-mint, minted ~59.47M PAID to themselves and
              sold into the market. The audited code was clean; the defect was the unguarded
              single-key upgrade (no timelock, no guardian, no multisig).
Reference:    Affected PAID ERC-20 contract: 0x1614f18fc94f47967a3fbe5ffcd46d4e7da3d787
                (reported total supply ~594,717,455 PAID; multi-source).
              Attacker address: only PARTIALLY public (SlowMist: begins 0x187..., ends ...65be);
                NOT reproduced in full in this fixture - not fabricated.
              Minted:  59,471,745.571 PAID (post-upgrade, by the hostile implementation).
              Sold:    2,501,203 PAID -> 2,040.4339 ETH (~$3M) on Uniswap before PAID blocked swaps.
              Nominal: ~$160M minted / ~$100M nominal value (sources vary; realized ~$3M).
              Date:    2021-03-05.
Post-mortems: PAID Network official (paidnetwork.medium.com, 2021-03-07); CertiK
              (certik.medium.com "PAID Network Post-Mortem"); Halborn
              (halborn.com/explained-the-paid-network-hack-march-2021); SlowMist
              (slowmist.medium.com). All public. No live RPC was used to build this fixture.
Source code:  ../PaidUpgradeClone.sol (authored minimized clone, this repo).
License:      MIT (this repo). No third-party code copied; only the proxy upgrade path + a
              mint-capable malicious implementation needed to replay the documented mechanism
              are modeled - PAID's full token/vesting logic is NOT reproduced.

Minimization: PaidTokenProxy (single-key instant upgradeTo + delegatecall to a swappable
              implementation over shared storage) + BenignPaidLogic (audited: plain transfer,
              no arbitrary-mint path) + MaliciousPaidLogic (the swapped-in code: mints an
              arbitrary amount to the attacker). Vesting, access-control details and the full
              ERC-20 surface are omitted - irrelevant to the unguarded-upgrade path.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/PaidUpgradeIncident.t.sol replays instant single-key upgradeTo(hostile) ->
              the hostile implementation mints MINTED to the attacker; the verdict is derived
              from the real outcome (attacker balance == MINTED and totalSupply inflated), not
              from addresses. A guard asserts the mint path did NOT exist before the upgrade
              (the same call reverts on the audited implementation), proving the unguarded
              upgrade is the enabler. Representative figures (INITIAL_SUPPLY, MINTED) follow the
              public reports; exact per-holder dilution is not part of the provenance.
              Expected: VULNERABLE (TP).
```
