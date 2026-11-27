// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/wallet_04_confused_sign.sol
//   original source : SmartContractSecurity/SWC-registry SWC-105
//   original license: MIT (SWC-registry is MIT)
//   upstream GT      : access_control, vulnerable_at_lines={30} (wrong comparison operator in withdraw)
//
// PORTED ^0.4.24 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Bug: withdraw() uses `>=` instead of `<=`, so a caller may request more than their balance.
// This is a comparison/logic bug, OUTSIDE drain-scan's scope. Expected behaviour: SILENT.
// IMPORTANT fidelity note: in >=0.8, the subsequent `balances[msg.sender] -= amount` reverts on
// underflow when amount > balance, so the drain is no longer runtime-exploitable after the port
// (it was in 0.4). The static pattern (wrong operator) is preserved for taxonomy comparison only.
// Port changes: `msg.sender.transfer`/`this.balance` modernized; removed the 0.4 overflow assert.
pragma solidity ^0.8.17;

contract Wallet {
    address creator;
    mapping(address => uint256) balances;

    constructor() {
        creator = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(amount >= balances[msg.sender]); // upstream vulnerable line: wrong operator
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function migrateTo(address to) public {
        require(creator == msg.sender);
        payable(to).transfer(address(this).balance);
    }
}
