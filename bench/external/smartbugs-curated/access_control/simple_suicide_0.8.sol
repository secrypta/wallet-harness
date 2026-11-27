// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/simple_suicide.sol
//   original source : SmartContractSecurity/SWC-registry test_cases/unprotected_critical_functions
//   original license: MIT (SWC-registry is MIT)
//   upstream GT      : access_control, vulnerable_at_lines={12,13} (unprotected selfdestruct)
//
// PORTED ^0.4.0 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Bug: unprotected `selfdestruct` (anyone can destroy the contract). This destroys the contract
// but does NOT install/seize an authority role, so it is OUTSIDE drain-scan's scope (R12 targets
// authority-role init-hijack, not bare selfdestruct). Expected scanner behaviour: SILENT.
// Port changes: explicit visibility; `selfdestruct(msg.sender)` -> `selfdestruct(payable(msg.sender))`.
pragma solidity ^0.8.17;

contract SimpleSuicide {
    function sudicideAnyone() public {
        selfdestruct(payable(msg.sender));
    }
}
