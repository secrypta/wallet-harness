# Fixture provenance

```
Fixture:      permit-phishing/b-incident/anyswap-permit-bypass-victim
Vector:       permit-phishing
Tier:         b-incident
Split:        holdout
Expected:     vuln

Origin:       Anyswap / Multichain AnyswapV4Router permit-validation bypass (2022-01-19, Ethereum).
              The router's `anySwapOutUnderlyingWithPermit` forwards a `permit(...)` to the
              underlying token and only requires that the call did not revert - it never checks
              that a valid signature actually granted an allowance. WETH has no `permit`, so the
              call hits WETH's permissive fallback and succeeds without verifying anything; the
              router then `transferFrom`s the underlying using the victim's PRE-EXISTING approval
              to the router. Anyone could drain any address that had approved the router.

Reference (authoritative write-up - facts verified by M against these):
              - coinspect "AnySwap Permit Attack" (learn-evm-attacks/cases/anyswap-permit-attack)
              - corroborated: BlockSec AnySwap rescue analysis; Zengo "Without Permit: Multichain's
                exploit explained".
              Date:        2022-01-19 (Ethereum)
              Attacker:    0xFA2731d0BEde684993AB1109DB7ecf5bF33E8051
              Router:      0x6b7a87899490EcE95443e979cA9485CBE7E71522 (AnyswapV4Router)
              Attack tx:   0xe50ed602bd916fc304d53c4fed236698b71691a95774ff0aeeb74b699c6227f7
                           (block 14037237)
              Amount:      976.8628 WETH stolen in total (Multichain post-mortem; USD varies by
                           source/date, ~$1.3M-$3M). The coinspect PoC demo (stole_WETH
                           constant) moves exactly 308636644758370382903 wei (~308.6366 WETH),
                           which this fixture uses verbatim.
              Victim:      0x3Ee505bA316879d246a8fD2b3d7eE63b51B44FAB - a REAL on-chain WETH source
                           in the attack tx (verified on Etherscan: 308.636 WETH drained from it);
                           used in the fixture as data, never as a detection signal.

Source code:  ../AnyswapRouterClone.sol (authored minimized clone, this repo).
License:      MIT (this repo). No third-party source copied; only the exploited
              anySwapOutUnderlyingWithPermit permit-trust + transferFrom surface and a WETH-like
              no-permit token with a permissive fallback are modeled. The cross-chain machinery
              and the malicious wrapper token are NOT reproduced.

Minimization: WethNoPermit (WETH-like ERC-20, no permit, permissive fallback) +
              AnyswapV4RouterClone.anySwapOutUnderlyingWithPermit. The real exploit deployed a
              malicious AnySwap-compatible token whose underlying was WETH; its exploited essence
              collapses to: the router forwards permit(...) to the underlying, requires only that
              the call did not revert (WETH's fallback accepts it), then transferFroms the
              underlying using the victim's pre-existing router approval. The cross-chain
              machinery and wrapper token are irrelevant to the permit-trust bug and are omitted.

Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.

Honesty:      Genuine `holdout` - authored after wal froze at v0.1 and NOT tuned to pass. The
              verdict is derived from the real outcome of the offline replay (the victim's balance
              leaves it), not hardcoded and not from matching attacker addresses. The attacker,
              router and tx are the real documented identifiers (verified against coinspect and
              Etherscan); the victim address is also real on-chain (the WETH source in the tx).
              NB: the attack tx is labeled 'Multichain Exploiter 4 (Whitehat)' on Etherscan - a
              rescue via the same permit-bypass path; the exploited mechanism is identical.
              test/AnyswapIncident.t.sol replays approve(router) -> anySwapOutUnderlyingWithPermit
              and reports the verdict. Expected: VULNERABLE (TP on split=holdout).
```
