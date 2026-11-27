// SPDX-License-Identifier: Apache-2.0
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/incorrect_constructor_name1.sol
//   original source : crytic/not-so-smart-contracts (formerly trailofbits), wrong_constructor_name (author: Ben Perez)
//   original license: Apache-2.0 (verified 2026-11-14)
//   upstream GT      : access_control, vulnerable_at_lines={20} (IamMissing unguarded owner setter)
//
// PORTED ^0.4.24 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// NOTE on semantics: the original bug is a "wrong constructor name" (a function that LOOKS like a
// constructor but is a plain public function). That specific class does not exist in >=0.5 (ctors
// use `constructor`). The RESIDUAL defect is an externally-callable, unguarded function that
// installs the `owner` authority - which is exactly what drain-scan R12 (init-hijack) targets.
// Port changes: `function () payable {}` -> `receive()`; `owner.transfer(this.balance)` ->
//   `payable(owner).transfer(address(this).balance)`.
pragma solidity ^0.8.17;

contract Missing {
    address private owner;

    modifier onlyowner {
        require(msg.sender == owner);
        _;
    }

    // unguarded authority setter (upstream vulnerable line)
    function IamMissing() public {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdraw() public onlyowner {
        payable(owner).transfer(address(this).balance);
    }
}
