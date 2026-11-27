Fixture:      eip7702-delegation/c-safe-impl/allowlisted-deleg-safe
Vector:       eip7702-delegation
Tier:         c-safe-impl
Expected:     safe

Origin:       Canonical defense for EIP-7702 delegation abuse: honor a delegation only to an
              allow-listed, audited delegate and refuse unknown ones.
Reference:    EIP-7702 (Pectra, 2025) delegation model; wallet threat guidance to restrict 7702
              delegation to audited delegates (Wintermute / Scam Sniffer analyses).
Source code:  AllowlistedDelegatePolicy.sol - reference-impl authored in this repo.
License:      MIT (this repo).

Minimization: REFERENCE-IMPL, honestly marked: EIP-7702 is a brand-new primitive with no single
              canonical audited third-party library yet, so tier (c) is a faithful implementation
              of the defense (allow-list of audited delegates), NOT vendored code and NOT a
              lightly-edited toy.
Offline:      Fully offline; deterministic Foundry test in Docker.
Notes:        The attacker's reusable sweeper is never allow-listed, so honorDelegation reverts
              and the drain path is unreachable. A guard installs and runs an allow-listed audited
              delegate, so BLOCKED is not vacuous. Harness MUST stay silent (BLOCKED).
