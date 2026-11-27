// SPDX-License-Identifier: Apache-2.0
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated @ 230e649123477eff332742a59a1c7cc6dc286cab (2026-11-14)
//                     path dataset/access_control/rubixi.sol
//   original source : crytic/not-so-smart-contracts (formerly trailofbits), wrong_constructor_name/Rubixi
//                     (real deployed contract 0xe82719202e5965Cf5D9B6673B7503a3b92DE20be)
//   original license: Apache-2.0 (verified 2026-11-14)
//   upstream GT      : access_control, vulnerable_at_lines={23,24} (DynamicPyramid unguarded creator setter)
//
// PORTED ^0.4.15 -> ^0.8.17 (not byte-identical). Value = taxonomy-agreement.
// Bug (the historical Rubixi incident): the function meant to be the constructor is named
// `DynamicPyramid()` (contract is `Rubixi`), so it stayed callable by anyone -> anyone could set
// themselves as `creator` and drain the collected fees. In >=0.5 the wrong-name class vanishes;
// the residual defect is an externally-callable, unguarded authority (creator) setter -> R12.
// Port changes: `throw` -> `revert()`; `constant` -> `view`; added explicit visibility; unnamed
//   fallback running init() -> `receive()`; `addr.send(x)` -> `payable(addr).send(x)` (return left
//   unchecked, as in the original); modernized string returns. Logic preserved.
pragma solidity ^0.8.17;

contract Rubixi {
    uint private balance = 0;
    uint private collectedFees = 0;
    uint private feePercent = 10;
    uint private pyramidMultiplier = 300;
    uint private payoutOrder = 0;

    address private creator;

    // Sets creator - upstream vulnerable lines: intended as a constructor but callable by anyone.
    function DynamicPyramid() public {
        creator = msg.sender;
    }

    modifier onlyowner {
        if (msg.sender == creator) _;
    }

    struct Participant {
        address etherAddress;
        uint payout;
    }

    Participant[] private participants;

    receive() external payable {
        init();
    }

    function init() private {
        if (msg.value < 1 ether) {
            collectedFees += msg.value;
            return;
        }
        uint _fee = feePercent;
        if (msg.value >= 50 ether) _fee /= 2;
        addPayout(_fee);
    }

    function addPayout(uint _fee) private {
        participants.push(Participant(msg.sender, (msg.value * pyramidMultiplier) / 100));

        if (participants.length == 10) pyramidMultiplier = 200;
        else if (participants.length == 25) pyramidMultiplier = 150;

        balance += (msg.value * (100 - _fee)) / 100;
        collectedFees += (msg.value * _fee) / 100;

        while (balance > participants[payoutOrder].payout) {
            uint payoutToSend = participants[payoutOrder].payout;
            payable(participants[payoutOrder].etherAddress).send(payoutToSend);
            balance -= participants[payoutOrder].payout;
            payoutOrder += 1;
        }
    }

    function collectAllFees() public onlyowner {
        if (collectedFees == 0) revert();
        payable(creator).send(collectedFees);
        collectedFees = 0;
    }

    function collectFeesInEther(uint _amt) public onlyowner {
        _amt *= 1 ether;
        if (_amt > collectedFees) collectAllFees();
        if (collectedFees == 0) revert();
        payable(creator).send(_amt);
        collectedFees -= _amt;
    }

    function collectPercentOfFees(uint _pcent) public onlyowner {
        if (collectedFees == 0 || _pcent > 100) revert();
        uint feesToCollect = collectedFees / 100 * _pcent;
        payable(creator).send(feesToCollect);
        collectedFees -= feesToCollect;
    }

    function changeOwner(address _owner) public onlyowner {
        creator = _owner;
    }

    function changeMultiplier(uint _mult) public onlyowner {
        if (_mult > 300 || _mult < 120) revert();
        pyramidMultiplier = _mult;
    }

    function changeFeePercentage(uint _fee) public onlyowner {
        if (_fee > 10) revert();
        feePercent = _fee;
    }

    function currentMultiplier() public view returns (uint multiplier, string memory info) {
        multiplier = pyramidMultiplier;
        info = "x100 fractional multiplier; capped 3x max, 1.2x min.";
    }

    function currentFeePercentage() public view returns (uint fee, string memory info) {
        fee = feePercent;
        info = "Shown in % form; halved for amounts >= 50 ether; capped at 10%.";
    }

    function totalParticipants() public view returns (uint count) {
        count = participants.length;
    }

    function numberOfParticipantsWaitingForPayout() public view returns (uint count) {
        count = participants.length - payoutOrder;
    }

    function participantDetails(uint orderInPyramid) public view returns (address addr, uint payout) {
        if (orderInPyramid < participants.length) {
            addr = participants[orderInPyramid].etherAddress;
            payout = participants[orderInPyramid].payout / 1 ether;
        }
    }
}
