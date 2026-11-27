// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
//
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated  (repo code Apache-2.0)
//                     commit 230e649123477eff332742a59a1c7cc6dc286cab (retrieved 2026-11-14)
//                     path   dataset/access_control/multiowned_vulnerable.sol
//   original source : SmartContractSecurity/SWC-registry
//                     test_cases/solidity/unprotected_critical_functions/multiowned_vulnerable
//   original license: MIT  (SWC-registry is MIT)
//   upstream GT      : category=access_control, vulnerable_at_lines={38} (newOwner missing onlyOwner)
//
// PORTED ^0.4.23 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Port changes: `!= 0` on address -> `!= address(0)`; assign `0` to address -> `address(0)`;
//   `this.balance` -> `address(this).balance`; `function() payable` -> `receive()`;
//   explicit visibility/`payable` on the ether-moving function.
// Bug preserved: newOwner() lacks the onlyOwner modifier, so anyone can enroll themselves
// as an owner. This is a GENERIC access-control defect (missing modifier), OUTSIDE the
// wallet-drain scope drain-scan is designed for (approval/signature/delegatecall/upgrade).
// Expected scanner behaviour: SILENT (scope boundary, not a false negative - see README).
pragma solidity ^0.8.17;

contract MultiOwnable {
  address public root;
  mapping (address => address) public owners; // owner => parent of owner

  constructor() {
    root = msg.sender;
    owners[root] = root;
  }

  modifier onlyOwner() {
    require(owners[msg.sender] != address(0));
    _;
  }

  // NOTE: the "onlyOwner" modifier is missing here (upstream vulnerable line).
  function newOwner(address _owner) external returns (bool) {
    require(_owner != address(0));
    owners[_owner] = msg.sender;
    return true;
  }

  function deleteOwner(address _owner) onlyOwner external returns (bool) {
    require(owners[_owner] == msg.sender || (owners[_owner] != address(0) && msg.sender == root));
    owners[_owner] = address(0);
    return true;
  }
}

contract TestContract is MultiOwnable {
  function withdrawAll() onlyOwner external {
    payable(msg.sender).transfer(address(this).balance);
  }

  receive() external payable {}
}
