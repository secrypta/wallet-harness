Fixture:      create2-metamorphic/c-safe-impl/codehash-pinned-safe
Vector:       create2-metamorphic
Tier:         c-safe-impl
Expected:     safe

Origin:       Canonical defense: codehash pinning. Record EXTCODEHASH of an approved/trusted
              contract at approve time and refuse the drain path if the code at that address
              later differs (a metamorphic swap) or is empty.
Reference:    MixBytes metamorphic analysis; general codehash-pinning guidance for approvals.
Source code:  CodehashPinnedVault.sol - reference-impl authored in this repo.
License:      MIT (this repo).

Minimization: REFERENCE-IMPL, honestly marked: no single canonical third-party library covers
              "don't trust a metamorphic approved address", so tier (c) is a faithful
              implementation of codehash pinning, NOT vendored code and NOT a lightly-edited toy.
              It grants no raw standing allowance; it re-verifies the spender's effective code
              identity on every outflow.
Offline:      Fully offline; deterministic Foundry test in Docker.
Notes:        After the metamorphic swap the pinned code identity no longer matches, so the
              guarded settlement reverts and nothing leaves. A guard settles with unchanged code,
              so BLOCKED is not vacuous. Harness MUST stay silent (BLOCKED).
