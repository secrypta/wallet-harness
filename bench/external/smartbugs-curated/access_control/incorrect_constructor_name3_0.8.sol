// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/incorrect_constructor_name3.sol
//   original source : SmartContractSecurity/SWC-registry SWC-118 (author: Ben Perez)
//   original license: MIT (SWC-registry is MIT)
//   upstream GT      : access_control, vulnerable_at_lines={17} (Constructor() unguarded owner setter)
//
// PORTED ^0.4.24 -> ^0.8.17 (not byte-identical). See incorrect_constructor_name1_0.8.sol header
// for the wrong-constructor-name -> residual unguarded authority-setter (R12) note.
// Port changes: `function () payable {}` -> `receive()`; transfer modernized.
pragma solidity ^0.8.17;

contract Missing {
    address private owner;

    modifier onlyowner {
        require(msg.sender == owner);
        _;
    }

    // unguarded authority setter (upstream vulnerable line); note: `Constructor` is just a
    // regular function name here, not a real constructor.
    function Constructor() public {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdraw() public onlyowner {
        payable(owner).transfer(address(this).balance);
    }
}
