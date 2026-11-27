// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyTokenFixture} from "../fixtures/approve-drainer/c-safe-impl/SoladyERC20Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT: drains revert against UNMODIFIED Solady ERC20.
/// @notice Solady (Vectorized/solady, MIT) is an independent ERC-20 / EIP-2612 implementation
///         the wal detectors were NEVER tuned against. These two targets are the honest
///         PRECISION test on unseen safe code: the harness MUST stay silent (verdict BLOCKED,
///         label safe) - a false positive here would be a real, recorded result, not hidden.
///
///         split=holdout. The allowance accounting and the `permit` signature check that stop
///         each drain are Solady's unmodified code, not a tweaked toy.
contract RealSafeSoladyHoldoutTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18;
    address constant HOLDER = address(0xB0B);
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory vector, string memory target, bool drained) internal pure {
        console.log(
            string.concat("[", vector, "] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// approve-drainer, real-safe holdout: bounded approve on Solady ERC20. Over-draw reverts.
    function test_approveDrainer_soladySafe_blocked() public {
        SoladyTokenFixture token = new SoladyTokenFixture();
        token.mint(HOLDER, START_BALANCE);

        // bounded authorization: exactly the action amount
        vm.prank(HOLDER);
        token.approve(ATTACKER, ACTION_AMOUNT);

        // Guard: the authority is REAL - the spender can move up to the bounded amount.
        vm.prank(ATTACKER);
        token.transferFrom(HOLDER, ATTACKER, ACTION_AMOUNT);
        assertEq(token.balanceOf(ATTACKER), ACTION_AMOUNT, "bounded spend should succeed");

        // Vector: pulling the remaining full balance must revert (Solady allowance check).
        uint256 remaining = token.balanceOf(HOLDER);
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady ERC20: InsufficientAllowance
        token.transferFrom(HOLDER, ATTACKER, remaining);

        bool drained = (token.balanceOf(HOLDER) < remaining);
        _report("approve-drainer", "solady-erc20-safe", drained);

        assertFalse(drained, "real-safe Solady wallet must not be drainable beyond the bound");
        assertEq(token.balanceOf(HOLDER), remaining, "balance must stay intact");
    }

    /// permit-phishing, real-safe holdout: a FORGED EIP-2612 permit is rejected by Solady.
    /// @dev This is precisely the forgery that broke Lixir (see the lixir-permit-victim vuln
    ///      holdout): a dummy signature. Solady's `permit` requires the recovered signer to
    ///      equal the owner, so no allowance is granted and the drain cannot proceed.
    function test_permitPhishing_soladySafe_blocked() public {
        SoladyTokenFixture token = new SoladyTokenFixture();
        token.mint(HOLDER, START_BALANCE);

        uint256 deadline = block.timestamp + 1 days; // not expired: exercise the SIGNATURE check
        // Forged signature: not produced from HOLDER's key over the permit digest.
        uint8 v = 27;
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));

        // Phishing attempt: forge a permit granting the attacker a full allowance. Must revert.
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady ERC20: InvalidPermit (recovered signer != owner)
        token.permit(HOLDER, ATTACKER, START_BALANCE, deadline, v, r, s);

        // The forged permit granted nothing, so any transferFrom must also revert.
        bool allowanceGranted = token.allowance(HOLDER, ATTACKER) > 0;
        bool drained;
        if (allowanceGranted) {
            vm.prank(ATTACKER);
            try token.transferFrom(HOLDER, ATTACKER, START_BALANCE) {
                drained = token.balanceOf(HOLDER) == 0;
            } catch {}
        }
        _report("permit-phishing", "solady-permit-safe", drained);

        assertFalse(allowanceGranted, "forged permit must grant no allowance");
        assertFalse(drained, "real-safe Solady permit must not be drainable via a forged signature");
        assertEq(token.balanceOf(HOLDER), START_BALANCE, "balance must stay intact");
    }
}
