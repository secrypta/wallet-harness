// SPDX-License-Identifier: MIT
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/wallet_02_refund_nosub.sol
//   original source : SmartContractSecurity/SWC-registry SWC-105
//   original license: MIT (SWC-registry is MIT)
//   upstream GT      : access_control, vulnerable_at_lines={36} (refund does not zero balance)
//
// PORTED ^0.4.24 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Bug: refund() transfers the caller's balance without zeroing it, so it can be called repeatedly
// to drain the contract. This is a STATE-update logic bug, not an approval/signature/delegatecall/
// upgrade/init-hijack vector, so it is OUTSIDE drain-scan's scope. Expected behaviour: SILENT.
// (Also note: in >=0.8 the subsequent `balances -= amount` in withdraw reverts on underflow, so
// the original overflow framing partly changes; the refund logic bug itself is preserved.)
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
        require(amount <= balances[msg.sender]);
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }

    function refund() public {
        // upstream vulnerable line: balance is not set to 0 after refund
        payable(msg.sender).transfer(balances[msg.sender]);
    }

    function migrateTo(address to) public {
        require(creator == msg.sender);
        payable(to).transfer(address(this).balance);
    }
}
