# Fixture provenance

```
Fixture:      address-poisoning/c-safe-impl/oz-erc20-benign-nearcollision-safe
Vector:       address-poisoning
Tier:         c-safe-impl  (precision / 0-false-positive control)
Expected:     safe                     # ground-truth label (matches meta `label`)

This fixture has TWO parts, kept explicitly separate for honesty:

(1) REAL third-party safe code - the transfer:
    The asset and its `transfer` are the UNMODIFIED OpenZeppelin ERC20.
      source : github.com/OpenZeppelin/openzeppelin-contracts
      tag    : v5.1.0
      commit : 69c8def5f222ff96f2b5beff05dfba996368aa79
      license: MIT (see fixtures/vendor/oz/LICENSE)
      used via: fixtures/approve-drainer/c-safe-impl/OZERC20Fixture.sol (a concrete OZ ERC20;
               adds only a test-only `mint` + constructor, no change to transfer/auth logic).
    A legitimate ERC20.transfer to the correct recipient is the real code path exercised here.

(2) AUTHORED synthetic scenario - the benign near-collision (NOT a real incident):
    There is NO real-world "benign collision" incident to cite, and NO third-party on-chain
    library that defends against address poisoning (the defence is wallet/UX: verify the FULL
    address, not the truncated 0x1234...cdef display). So the SCENARIO around the real transfer
    is authored in this repo: two addresses that share the displayed prefix+suffix (0xDEAD..BEEF)
    but differ in the full address; the user pays the verified INTENDED one. This is a
    deliberately synthetic PRECISION control, not an independent real-world safe implementation,
    and is NOT claimed as a `split=holdout` case.

Why it matters (precision / 0-FP): the address-poisoning detector keys on funds reaching a
    look-alike that shares the truncated display with a verified/prior counterparty. This fixture
    is the honest complement: a near-collision EXISTS, yet the send is legitimate (to the verified
    full address). The detector MUST stay silent here - flagging it would be a false positive.
    Outcome: funds reach INTENDED, the decoy receives nothing -> not misrouted -> BLOCKED (TN).

Relationship to verified-send-safe: that fixture shows a *policy* rejecting a poisoned look-alike
    (the user mistakenly targets the decoy). THIS fixture shows a *plain real OZ transfer* to the
    correct target must not be flagged merely because a near-collision exists in history. Together
    they pin both sides of the precision boundary without a poisoning drain.

Source code:  test/RealSafeAddressPoisoningNearCollision.t.sol (authored scenario);
              real transfer via OZERC20Fixture.sol -> fixtures/vendor/oz ERC20 (OZ v5.1.0, MIT).
License:      MIT (this repo) for the authored scenario; OZ v5.1.0 MIT for the vendored transfer.
Offline:      committed source only; no network, no live RPC. Built/run in Docker.
Notes:        test first asserts the near-collision premise (displayedMatches == true, full
              addresses differ), then performs the real OZ transfer to INTENDED and derives the
              verdict from the outcome (decoy balance == 0 -> BLOCKED). A balance assertion keeps
              BLOCKED non-vacuous (the real transfer did move funds, to the correct recipient).
```
