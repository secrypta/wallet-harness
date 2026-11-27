# Fixture provenance

```
Fixture:      permit-phishing/b-incident/lixir-permit-victim
Vector:       permit-phishing
Tier:         b-incident
Split:        holdout                   # authored after wal froze at v0.1 (see honesty note)
Expected:     vuln                      # ground-truth label (matches meta `label`)

Origin:       Lixir vault-token forged-permit approval drain
Reference:    Attacker EOA:       0x3fa8cf7fea68c8e76a9838d77889464ddfb6a6cf
              Helper contract:    0xefd1b12f5e3c35d7dae0d1449674c247566f9b76
              Vulnerable tokens:  six Lixir EIP-1167 vault-share clones (lv_WETH-USDC / lv_LIX-WETH
                                  / lv_USDC-USDT):
                                    0xfd4c9a491dd777b8b3e13659e9e379252ec78390
                                    0x49bba4c5c4f8a2d444ca5fda1b3137d94df40465
                                    0xc870d944dd883f25a1b7b3312bc2449dd5b0267d
                                    0xf4af7ae20eb7334cbdf334eaf850e7db42394839
                                    0xf4aada01bf9d44fe0d03a6b2fa6519e3d7325556
                                    0xecc2b0296eae113a114ccb9f8846a7852545dc58
              Attack tx:          0x17026faca0b8e4cb7531e4fb277c390eb165e81229628e0192923ad1d90a41da
                                  (block 25391316)
              Mechanism:          one non-owner signature tuple reused across 41 `permit` calls over
                                  35 distinct owners, then 39 `withdrawETHFrom` + 2 `withdrawFrom`
                                  consuming the forged approvals.
              Amount drained:     2.588255642603989317 ETH, 4,477.722585 USDC, 3,609.950462 USDT,
                                  24,182.560323103174179821 LIX (realizable loss ~$12.3K; LIX leg
                                  largely illiquid)
              Date: 2026-06-25 01:21:23 UTC (Ethereum)
              Source (authoritative write-up):
                https://www.darknavy.org/web3/exploits/lixir-vault-forged-permit-approval-drain/
                (corroborated: olympix.security exploit post-mortems; crypto.training/hacks). All public.
Source code:  ../LixirVaultTokenClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; only the broken `permit` (accepts any
              dummy signature whose ecrecover is nonzero, never checking recovered == owner) plus
              a minimal allowance/transferFrom surface are modeled. Vault accounting omitted.

Minimization: Modeled LixirVaultTokenClone with a `permit` that requires only
              `ecrecover(digest,v,r,s) != address(0)` - the documented bug - instead of
              `recovered == owner`. A forged dummy signature therefore grants the attacker an
              allowance, and `transferFrom` drains the holder. The holder in the test is an
              explicit stand-in (the real drain hit 35 distinct owners; their individual addresses
              are not reproduced here); the drained amounts are the darknavy-documented figures.
              The real attacker/token/tx identifiers above are used for fidelity only (labels,
              never a detection signal).
Offline:      committed minimized clone; no fork, no live RPC. Built/run in Docker.

Contrast:     the solady-permit-safe holdout is a CORRECT EIP-2612 permit (requires recovered ==
              owner) and rejects this exact forgery -> BLOCKED. Same vector, opposite verdict:
              the recall (this fixture) / precision (that one) pair on the permit-signature check.

Honesty:      Genuine `holdout` - authored after wal froze at v0.1 and NOT tuned to pass. The
              verdict is derived from the real outcome of the offline replay (the holder's
              balance leaves it), not hardcoded. test/LixirPermitIncident.t.sol replays the
              forged permit -> transferFrom and reports the verdict. Expected: VULNERABLE (TP).
```
