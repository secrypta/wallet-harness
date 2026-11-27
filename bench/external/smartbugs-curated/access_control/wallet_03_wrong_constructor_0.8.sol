// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/wallet_03_wrong_constructor.sol
//   original source : SmartContractSecurity/SWC-registry SWC-105
//   original license: MIT (SWC-registry is MIT)
//   upstream GT      : access_control, vulnerable_at_lines={19,20} (initWallet unguarded creator setter)
//
// PORTED ^0.4.24 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Residual defect after the wrong-constructor-name port: initWallet() installs `creator` with no
// guard -> R12 (init-hijack) target. Port changes: `msg.sender.transfer`/`this.balance` modernized.
pragma solidity ^0.8.17;

contract Wallet {
    address creator;
    mapping(address => uint256) balances;

    // unguarded authority setter (upstream vulnerable lines)
    function initWallet() public {
        creator = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(amount <= balances[msg.sender]);
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function migrateTo(address to) public {
        require(creator == msg.sender);
        payable(to).transfer(address(this).balance);
    }
}
