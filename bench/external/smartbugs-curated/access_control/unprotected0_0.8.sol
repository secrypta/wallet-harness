// SPDX-License-Identifier: Apache-2.0
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
//
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated  (repo code Apache-2.0)
//                     commit 230e649123477eff332742a59a1c7cc6dc286cab (retrieved 2026-11-14)
//                     path   dataset/access_control/unprotected0.sol
//   original source : https://github.com/crytic/not-so-smart-contracts
//                     (formerly trailofbits/not-so-smart-contracts) unprotected_function/Unprotected.sol
//   original license: Apache-2.0  (verified at crytic/not-so-smart-contracts, 2026-11-14)
//   upstream GT      : category=access_control, vulnerable_at_lines={25} (changeOwner unprotected)
//
// PORTED ^0.4.15 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Port changes: old-style constructor `function Unprotected()` -> `constructor()`.
// Bug preserved: changeOwner() lacks the onlyowner modifier, so anyone can seize ownership.
// GENERIC access-control defect (missing modifier), OUTSIDE drain-scan's wallet-drain scope.
// Expected scanner behaviour: SILENT (scope boundary, not a false negative - see README).
pragma solidity ^0.8.17;

contract Unprotected {
    address private owner;

    modifier onlyowner {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // This function should be protected (upstream vulnerable line).
    function changeOwner(address _newOwner) public {
        owner = _newOwner;
    }
}
