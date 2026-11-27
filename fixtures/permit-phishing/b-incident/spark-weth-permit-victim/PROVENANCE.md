# Fixture provenance

```
Fixture:      permit-phishing/b-incident/spark-weth-permit-victim
Vector:       permit-phishing
Tier:         b-incident
Expected:     vuln                     # ground-truth label (matches meta `label`)
Split:        holdout                  # authored after wal detectors froze at v0.1

Origin:       Spark WETH (spWETH) EIP-2612 permit-phishing drain, ~$32M. The victim signed ONE
              off-chain phishing EIP-2612 `permit` naming the attacker's drainer contract as
              `spender` with an unbounded `value`. The drainer submitted the permit to set the
              allowance and swept the victim's ENTIRE spWETH balance with TWO `transferFrom`
              calls that split the proceeds across two recipient wallets - all in one tx.
              spWETH is a Spark (Aave-v3-style) aToken; its EIP-2612 surface is the real token's,
              not Uniswap Permit2 (verified on-chain, see below).

On-chain (verified this session; drain tx receipt via read-only RPC + Etherscan):
  Network:    Ethereum mainnet
  Drain tx:   0xf7c00f18175cdea49f8fdad6a1d45edeb318f18f3009f51ab9f4675171c1d8fb
  Status:     Success
  Block:      20847274  (= 0x13e1aaa, derived from decimal programmatically)
  Timestamp:  2024-09-28 06:15:23 UTC
  Token:      0x59cd1c87501baa753d0b5b5ab5d8416a45cd71db  (ERC-20 "Spark WETH" / spWETH, 18 dec)
  Victim:     0xAA1582084c4f588eF9BE86F5eA1a919F86A3eE57  (owner who signed the phishing permit)
  Tx From:    0x0000db5c8B030ae20308ac975898E09741e70000  (Etherscan tag Fake_Phishing187019 -
              the drainer EOA that submitted the tx)
  Drainer:    0x33fff906795804fb77b0b11dffcf275cae08016c  (Etherscan tag Fake_Phishing573994 -
              contract created in-tx; the `spender` the victim's permit approved; it emitted the
              owner->spender Approval and executed the transferFrom sweeps)
  Entry call: 0xed0e416e0fEEA5b484ba5c95d375545AC2b60572  (Etherscan tag Fake_Phishing188615 -
              the tx `To`)
  Recipient1: 0x471C725bd1f29850cbb8EeA4CDf6C9cE3cAC5607  (Etherscan tag Fake_Phishing573943)
              amount 10,002.771096118655086354 spWETH
  Recipient2: 0xAA862F977d6916A1E89e856fC11FD99a2F2FaBF8  (Etherscan tag Fake_Phishing442846)
              amount 2,121.799929479714715287 spWETH
  Total out:  12,124.571025598369801641 spWETH from the victim (two ERC-20 Transfer logs).
  Mechanism:  VERIFIED EIP-2612 (NOT Uniswap Permit2). The tx receipt logs show the Approval
              events emitted by the spWETH token contract itself (owner=victim, spender=drainer
              contract); the canonical Uniswap Permit2 (0x000000000022D473030F116dDEE9F6B43aC78BA3)
              does NOT appear in any log. So the phished signature was an EIP-2612 token `permit`,
              which is why this is filed under permit-phishing, not permit2-phishing.

Reference (>= 2 independent authoritative sources + on-chain match):
  - CertiK (CertiK Alert): named the drained EOA 0xaa15...e57 (~12,083 spWETH, ~$32M) and the
    fund flow to 0x471c... then onward to four wallets.
  - Cointelegraph (and Yahoo Finance / Bitget syndication): "User loses $32 million spWETH in a
    sophisticated phishing attack", 2024-09-28, citing CertiK and Scam Sniffer.
  - Scam Sniffer (official @realScamSniffer): characterized the authorization as a phishing
    "permit" signature.
  - Etherscan's OWN phishing labels, maintained independently: the drainer EOA, the drainer
    contract and both recipient wallets are all tagged Fake_Phishing* - independent corroboration
    that this is a phishing drain, not a legitimate transfer.
  Proof level: STRONG for the on-chain drain (tx + status + block + timestamp + token + victim +
  drainer + two recipient amounts + mechanism, all verified on-chain and cross-checked against
  CertiK/Cointelegraph/ScamSniffer + Etherscan phishing labels).

Relationship to other fixtures (distinctness, honest):
  - DISTINCT from usdc-permit-victim: although both are EIP-2612 permit-phishing (the shared base
    mechanism of this vector), this is a different, independent, far larger incident - a
    different token (Spark aToken, 18 dec, domain version "1" vs USDC 6 dec, version "2"),
    different victim/tx/date/amount, and it models the real two-recipient split sweep rather than
    a single transferFrom. Not a near-duplicate.
  - DISTINCT from lixir-permit-victim (broken-permit, forged/dummy signature accepted) and
    anyswap-permit-bypass-victim (router permit-bypass -> standing-approval transferFrom): both a
    different enabling bug.
  - Honest note: the drainer EOA 0x0000db5c...0000 (tx From) is the SAME operator as in this
    repo's link-permit2-victim fixture, but that is a DIFFERENT incident (different token, victim,
    tx, and mechanism: EIP-2612 permit here vs Uniswap Permit2 there). The shared EOA is a label
    detail, never a detection signal.

Source code:  ../SparkWETHPermitClone.sol - a minimized, MIT, authored-here EIP-2612 permit token
              modeling exactly the ERC-20 + permit surface needed to replay the path. No
              third-party / exploit bytecode is copied or vendored. The owner used in the test is
              a test key (the real victim's key is unavailable); the real victim address is the
              documented on-chain identity above. Recipient/spender addresses in the test are the
              real Etherscan-labeled addresses, used as labels for fidelity. The swept amounts are
              the real on-chain values.
License:      MIT (this repo).
Offline:      committed; no mainnet fork, no live RPC in the test. Built/run in Docker.
Notes:        test/SparkWethPermitIncident.t.sol: ONE phishing permit sets an unbounded allowance,
              then two transferFrom calls empty the victim's spWETH. Verdict derived from the real
              outcome (balance == 0). Expected: VULNERABLE (TP).
```
