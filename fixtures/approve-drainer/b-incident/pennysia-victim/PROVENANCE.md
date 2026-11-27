# Fixture provenance

```
Fixture:      approve-drainer/b-incident/pennysia-victim
Vector:       approve-drainer
Tier:         b-incident
Split:        holdout
Expected:     vuln

Origin:       Pennysia Settlement stale-approval drain (2026-11-12). `PennysiaSettlement.executeSwap`
              takes a "route" = a venue address + raw calldata and executes it as a low-level call
              from the Settlement's own context, with no allow-listing of the venue or the call.
              Users had granted the Settlement a (stale) token approval, so an attacker crafted a
              route whose venue was the token and whose calldata was
              `transferFrom(victim, Settlement, amount)` - the Settlement is the approved spender,
              so the victim's standing allowance was spent. Arbitrary-callee / stale-approval class
              (relates to R11: an external call spends a victim's standing approval).

Reference (authoritative write-ups - facts verified by M against these; on-chain not manually
           re-verified by this track):
              - dev.to/pandasecurity (Panda Security write-up)
              - SlowMist alert (2026-11-13)
              Date:        2026-11-12 13:59:11 UTC (block 26399314, Ethereum mainnet; per the cited write-ups, on-chain trace not re-verified by this track)
              Attack tx:   0x2716c50e450272240f68f2827bcb4a336c2ac520951e0e530154566c295b732d
              Attacker EOA: 0x813a5ab666adeba907548235fbac087642878300
              Attacker helper: 0x96bb89e3f86312968ce11a1bd8d9d28f4891a17a
              Vulnerable:  PennysiaSettlement 0x3aad97e5a91b8e43b7dc830aceb004307678795e
              Loss:        ~$5,131 across 4 wallets (5,000 USDC + 6.133489 USDC + 0.05 wstETH +
                           101,000 YUNO; per-wallet, dev.to/pandasecurity). This fixture replays
                           the 5,000 USDC leg. (SlowMist's structured entry lists the total as
                           undisclosed/0; the ~$5,131 figure is from the pandasecurity write-up.)
              Victims:     truncated in the public sources -> used here as an EXPLICIT STAND-IN
                           (address(0xBEEF)), never as a detection signal.

Source code:  ../PennysiaSettlementClone.sol (authored minimized clone, this repo).
License:      MIT (this repo). No third-party source copied; only the exploited `executeSwap`
              arbitrary-(venue,calldata) forwarder + a minimal USDC-like allowance surface are
              modeled. The full routing/venue/settlement engine is NOT reproduced.

Minimization: MiniUSDC (6-decimal allowance/transferFrom) + PennysiaSettlementClone.executeSwap,
              which forwards an attacker-chosen (venue, calldata) as a low-level call. The real
              exploit routed transferFrom proceeds to the Settlement; this minimized replay routes
              them straight to the attacker - the exploited essence (an unrestricted external call
              spends the victim's stale approval to the Settlement) is identical.

Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.

Honesty:      Genuine `holdout` - authored after wal froze at v0.1 and NOT tuned to pass. The
              verdict is derived from the real outcome of the offline replay (the victim's balance
              leaves it), not hardcoded. The attacker/helper/Settlement/tx are the real documented
              identifiers (verified against the write-ups above, on-chain not re-verified here);
              the victim is an explicit stand-in as noted. test/PennysiaIncident.t.sol replays
              approve(Settlement) -> executeSwap(transferFrom route) and reports the verdict.
              Expected: VULNERABLE (TP on split=holdout).
```
