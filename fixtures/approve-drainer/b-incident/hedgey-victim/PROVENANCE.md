# Fixture provenance

```
Fixture:      approve-drainer/b-incident/hedgey-victim
Vector:       approve-drainer
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Split:        holdout

Origin:       Hedgey Finance ClaimCampaigns drain, 2024-04-19 (Balancer flash-loan funded).
Root cause:   ClaimCampaigns.createLockedCampaign lacked input validation on the `claimLockup`
              parameter, which carries the "locker" address the contract approves to move
              tokens. The attacker supplied their OWN contract as the locker, so the contract
              granted it a standing ERC-20 approval. When the campaign was cancelled, the
              contract returned the campaign's own deposit but DID NOT revoke that approval.
              The residual, unrevoked allowance then let the attacker's contract transferFrom
              the ClaimCampaigns contract's pooled balance (funds from other campaigns). Classic
              approve-drain: a standing/stale approval to an attacker-controlled spender, drained
              by transferFrom. Distinct from badger (front-end approval injection), transit
              (pre-existing USER approvals swept) and from malicious-calldata (arbitrary call).

On-chain verified (read-only RPC eth.drpc.org, Ethereum mainnet):
  ETH attack tx:  0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739
                  status=success, block 19687890
                  tx.from = 0xded2b1a426e1b7d415a40bcad44e98f47181dda2  (attacker EOA)
                  tx.to   = 0xc793113f1548b97e37c409f39244ee44241bf2b3  (attacker helper contract)
                  Transfer log: 1,303,910.12 USDC (0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48)
                  from 0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511 (ClaimCampaigns)
                  -> 0xded2b1a426e1b7d415a40bcad44e98f47181dda2 (attacker).
  Timestamp 2024-04-19 07:06:47 UTC per Hedgey official post-mortem (block 19687890).

Key addresses:
  Attacker (EOA):                       0xded2b1a426e1b7d415a40bcad44e98f47181dda2
  Exploited ClaimCampaigns contract:    0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511
                                        (same address deployed on 5 chains per CertiK/TechFlow)

Sources (>=3 independent, mutually consistent, consistent with on-chain):
  - Halborn:      https://www.halborn.com/blog/post/explained-the-hedgey-finance-hack-april-2024
                  (root cause: createLockedCampaign missing validation on claimLockup; approvals
                   created by the bad call then used to move tokens in a follow-up tx).
  - CertiK:       https://www.certik.com/resources/blog/hedgey-finance-incident-analysis
  - TechFlow:     https://www.techflowpost.com/en-US/article/17512 (names the stale-approval
                  mechanism, ClaimCampaigns 0xbc452fdc..., tx 0x2606d459..., 1,303,910.12 USDC).
  - ImmuneBytes:  https://immunebytes.com/blog/?p=11264  (~$2M ETH, BONUS on Arbitrum).
  - Rekt:         https://rekt.news/hedgey-finance-rekt  ($2.1M ETH + $42.6M Arbitrum).
  Loss totals differ between outlets ($44.5-48M headline); the pinned ETH USDC figure
  (1,303,910.12) is consistent across sources and matches the on-chain Transfer log exactly.

Source code:  ../HedgeyClaimCampaignsClone.sol (authored minimized MIT clone, this repo).
License:      MIT (this repo). No third-party code copied. DeFiHackLabs (Apache-2.0) used only
              as a FACTS reference (tx/addresses), never vendored or copied.

Call shapes:  FAITHFUL to the real contract. The real ClaimCampaigns grants the allowance via the
              OZ SafeERC20 library static helper `SafeERC20.safeIncreaseAllowance(IERC20(token),
              locker, amount)` (spender = 2nd arg) and pulls the deposit via its own
              `TransferHelper.transferTokens(token, from, address(this), amount)` library helper
              (SafeERC20.safeTransferFrom under the hood) - NOT the bare `token.approve(...)` /
              `token.transferFrom(...)` member forms. The clone reproduces these library forms so
              the committed gate exercises exactly the shape a member-only scan is blind to
              (the real-case gap that this fixture exists to close).

Minimization: Modeled only approve-on-create (with an unvalidated locker) + no-revoke-on-cancel,
              plus a minimal USDC-like ERC-20. The real vesting/lockup plan accounting, the
              flash-loan entry, campaign claim math and multi-chain deployment are omitted -
              irrelevant to the approve-drain path. Real addresses above are used as-is for
              fidelity only (never a detection signal). The pooled "other campaigns" balance is
              modeled with a top-up because the single standing approval drained funds beyond
              the cancelled campaign's own deposit.
Offline:      committed minimized clone; no mainnet fork, no live RPC at test time. Built/run in
              Docker.
Notes:        test/HedgeyIncident.t.sol replays create (standing approve to attacker locker) ->
              cancel (approval NOT revoked) -> attacker transferFrom, and derives the verdict
              from the real outcome (contract emptied). Expected: VULNERABLE (TP).
```
