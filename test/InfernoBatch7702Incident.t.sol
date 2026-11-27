// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    MiniToken,
    Call,
    InfernoAccount,
    InfernoBatchDrainer
} from "../fixtures/eip7702-delegation/b-incident/InfernoBatchDrainerClone.sol";

/// @title eip7702-delegation (b) real-incident HOLDOUT: Inferno Drainer batched 7702 sweep (2025-05).
/// @notice Minimized OFFLINE replay (no live RPC): a victim phished into a 7702 delegation to the
///         Inferno batch drainer is emptied of MULTIPLE assets (ETH + two ERC-20s) in a single
///         atomic activation. The verdict is derived from the real outcome (every asset left the
///         account), not hardcoded. Distinct from the CrimeEnjoyor dev fixture (single reusable
///         single-asset sweeper). HOLDOUT: wal was NOT tuned to pass it (label=vuln -> VULNERABLE).
contract InfernoBatch7702IncidentTest is Test {
    address constant ATTACKER = address(0xBAD);
    uint256 constant ETH_BAL = 5 ether;
    uint256 constant TK_A = 1_000e18;
    uint256 constant TK_B = 2_500e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_infernoBatch7702Incident_isDrained() public {
        InfernoAccount account = new InfernoAccount();
        MiniToken a = new MiniToken();
        MiniToken b = new MiniToken();

        // Fund the victim account with native ETH and two ERC-20 positions.
        vm.deal(address(account), ETH_BAL);
        a.mint(address(account), TK_A);
        b.mint(address(account), TK_B);

        // Victim is phished into delegating the EOA to the Inferno batch drainer.
        InfernoBatchDrainer drainer = new InfernoBatchDrainer();
        account.installDelegation(address(drainer));

        // One atomic activation sweeps every asset at once (the 7702 batch).
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: address(0), amount: ETH_BAL}); // native
        calls[1] = Call({target: address(a), amount: TK_A});
        calls[2] = Call({target: address(b), amount: TK_B});
        account.activate(abi.encodeWithSelector(InfernoBatchDrainer.drainBatch.selector, ATTACKER, calls));

        bool drained =
            ATTACKER.balance == ETH_BAL &&
            a.balanceOf(ATTACKER) == TK_A &&
            b.balanceOf(ATTACKER) == TK_B &&
            address(account).balance == 0 &&
            a.balanceOf(address(account)) == 0 &&
            b.balanceOf(address(account)) == 0;
        _report("inferno-batch7702-victim", drained);

        assertTrue(drained, "one batched 7702 activation should sweep every asset");
        assertEq(ATTACKER.balance, ETH_BAL, "attacker received the native balance");
        assertEq(a.balanceOf(ATTACKER), TK_A, "attacker received token A");
        assertEq(b.balanceOf(ATTACKER), TK_B, "attacker received token B");
    }
}
