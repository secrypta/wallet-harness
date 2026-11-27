# Fixture provenance

```
Fixture:      malicious-calldata/b-incident/rabby-swaprouter-victim
Vector:       malicious-calldata
Tier:         b-incident
Split:        holdout  (authored after wal detectors froze at v0.1; genuine independence)
Expected:     vuln

Origin:       Rabby Wallet Swap router exploit, 2022-10-11, Ethereum (+BNB Chain), ~$200K
              (114 ETH + 179 BNB) drained from users who had approved the swap router after
              Rabby launched its in-wallet Swap feature (~2022-09-14). The swap contract
              executed a caller-supplied call TARGET and CALLDATA (via OpenZeppelin's Address
              `functionCallWithValue`) with no validation of either. The attacker pointed the
              target at victims' tokens and supplied transferFrom(victim, attacker, amount);
              the router executed it as msg.sender and pulled the victims' standing approvals.
              Rabby reimbursed affected users; the contract was never paused, so lingering
              approvals to it remain dangerous.
Root cause:   Unvalidated caller-supplied call target + calldata executed by an in-wallet swap
              router (arbitrary external-call injection), draining standing approvals. Same
              approval-drain class as Socket / LI.FI / Transit / Rubic / Dexible / Seneca /
              Unizen; distinct incident/protocol (a consumer wallet's own swap router).

On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
  Attack tx:  0x914c1ae4f03657064f0b1d5ddc6e06f39e82bce6fb2f726efdca52c092fbfc26  (Ethereum)
              from  0xb687550842a24d7fbc6aad238fd7e0687ed59d55  (attacker EOA)
              to    0x9682f31b3f572988f93c2b8382586ca26a866475  (attacker exploit contract)
              block 15724452, timestamp 2022-10-11 11:04:23 UTC
  Rabby Swap router (victim contract approved by users): 0x6eb211caf6d304a76efe37d9abdfaddc2d4363d1
  The on-chain from/to match the attacker EOA and exploit contract documented by DeFiHackLabs /
  SlowMist, cross-confirming the tx hash. (The attacker ran several drain txs; one is pinned here.)

Sources (>=3 independent, authoritative; facts agree across them and with on-chain):
  1. SlowMist (via Coinlive) - "Rabby Swap has an external call risk; ~$190K profit"
     https://www.coinlive.com/news-flash/4620
  2. Neptune Mutual - "Decoding Rabby's Smart Contract Vulnerability" (functionCallWithValue;
     unchecked target + calldata; transferFrom against approvals)
     https://medium.com/neptune-mutual/decoding-rabbys-smart-contract-vulnerability-873120014c22
  3. web3isgoinggreat - "Rabby Wallet's swap feature exploited a month after launch"
     https://www.web3isgoinggreat.com/?id=rabby-swap-exploited-a-month-after-launch
  4. revoke.cash - "2022 Rabby Swap Hack: Check If You're Affected" (approval risk persists)
     https://revoke.cash/exploits/rabby
  5. Halborn - "A 'Hat Trick' of DeFi Hacks" (covers the Rabby swap exploit)
     https://www.halborn.com/blog/post/a-hat-trick-of-defi-hacks-underscores-the-importance-of-defi-security
  Loss ~$200K (114 ETH + 179 BNB) across sources; representative, not asserted as exact.

Source code:  ./RabbySwapRouterClone.sol (authored minimized clone of the vulnerable swap path,
              this repo) + src/MockERC20.sol (the approved token).
License:      MIT (this repo). No third-party bytecode copied. DeFiHackLabs (Apache-2.0) used
              only as a reference for the attack tx / addresses; its PoC code was NOT vendored.
Minimization: Only the vulnerable surface is modeled - a swap that executes a caller-supplied
              target + calldata with no validation. The multi-DEX routing is omitted.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Notes:        test/RabbySwapRouterIncident.t.sol: the attacker calls swap with swapTarget=token
              and transferFrom(victim -> attacker) as calldata, draining the approval.
              Expected: VULNERABLE (TP).
```
