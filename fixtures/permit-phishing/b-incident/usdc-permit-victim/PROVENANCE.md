# Fixture provenance

```
Fixture:      permit-phishing/b-incident/usdc-permit-victim
Vector:       permit-phishing
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)

Origin:       USDC ERC-2612 `permit` phishing drain (selector 0xd505accf)
Reference:    Drain tx (permit consumed + transferFrom in one tx):
                0xfd7417af8433e3d9bcbed3f965307c800a24eb4e98f42cebfab6ca6064f5a642
              Block: 24671606   Date: 2026-03-16 17:38:59 UTC
              Victim (permit owner):        0x051bb76ff78366de530e293fdb1158c2079ab664
              Attacker EOA:                 0xafb2423f447d3e16931164c9970b9741aab1723e
              Permit spender / drainer:     0x0927ba1f2a31875b0dd7b28eec3a3e74b4620653
              USDC token:                   0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
              Permit value = MAX_UINT256, deadline = never (type(uint256).max)
              Source (authoritative write-up):
                https://www.darknavy.org/web3/exploits/usdc-permit-phishing-drain/
                (amount 1,766,308.432620 USDC; EIP-7702 poisoner 0x9F68523e... in a prior
                interaction, out of scope here). All public.
Source code:  ../USDCPermitClone.sol (authored minimized clone, this repo)
License:      MIT (this repo). No third-party code copied; only the ERC-20 + EIP-2612 permit
              surface is modeled (name "USD Coin" / version "2" match USDC's EIP-712 domain).

Minimization: Modeled `permit` (strict ecrecover/deadline/nonce), `approve`, `transferFrom`
              with standard allowance accounting; 6 decimals like USDC. Blacklist, upgrade
              proxy, FiatToken minting/roles omitted - irrelevant to the permit-drain path.
Offline:      committed minimized clone; no mainnet fork, no live RPC. Built/run in Docker.
Representative / not exact:
              - The permit OWNER in the test is a key-derived stand-in (vm key 0xC0DE).
                EIP-2612 requires a valid owner signature and the real victim's private key
                is (rightly) not public, so the real address 0x051bb7...9ab664 is cited here
                but cannot be signed for. The attacker (0xAfb2...) and spender (0x0927...)
                addresses are used as-is.
              - VICTIM_BALANCE (1,766,308.43 USDC) is the documented total drained, used as
                the single-victim balance for the minimized replay.
Notes:        The real incident also chained an EIP-7702 delegation (poisoner
              0x9F68523efdc91ADbE53c3776Aa927f41aB4FE17E) - out of scope here; that belongs
              to the reserved eip7702-delegation vector and is deliberately NOT reproduced.
              test/UsdcPermitIncident.t.sol replays permit(value=max) -> transferFrom and
              the verdict is derived from the real outcome (balance emptied). Expected:
              VULNERABLE (TP).
```
