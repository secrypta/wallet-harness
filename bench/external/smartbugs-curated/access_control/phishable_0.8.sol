// SPDX-License-Identifier: CC-BY-4.0
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/phishable.sol
//   original source : https://github.com/sigp/solidity-security-blog (Adrian Manning)
//   original license: CC-BY-4.0 (verified 2026-11-14)
//   upstream GT      : access_control, vulnerable_at_lines={20} (tx.origin authorization)
//
// PORTED ^0.4.22 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Bug: authorization via `tx.origin` (phishing). This is OUTSIDE drain-scan's scope (not an
// approval/signature/delegatecall/upgrade/init-hijack drain). Expected scanner behaviour: SILENT
// (scope boundary, not a false negative). Port changes: explicit visibility; `function() public
// payable` -> `receive()`; `_recipient.transfer(this.balance)` modernized.
pragma solidity ^0.8.17;

contract Phishable {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {} // collect ether

    function withdrawAll(address _recipient) public {
        require(tx.origin == owner); // tx.origin auth (upstream vulnerable line)
        payable(_recipient).transfer(address(this).balance);
    }
}
