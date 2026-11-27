// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyTokenFixture} from "../fixtures/approve-drainer/c-safe-impl/SoladyERC20Fixture.sol";
import {SoladySafeTransferLibWallet} from
    "../fixtures/approve-drainer/c-safe-impl/solady-safetransferlib-safe/SoladySafeTransferLibWallet.sol";

/// @title Tier-(c) real-safe HOLDOUT: scoped approve-and-revoke over the REAL Solady
///        SafeTransferLib (approve-drainer vector).
/// @notice The approval helper (`SafeTransferLib.safeApprove`) and the over-draw revert (Solady
///         ERC20 allowance accounting) are Solady's unmodified code - an independent codebase
///         the wal detectors were NEVER tuned against. split=holdout: the harness MUST stay
///         silent (verdict BLOCKED, label safe); a false positive here would be a real, recorded
///         result, not hidden.
contract RealSafeSafeTransferLibHoldoutTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // exactly what the legit interaction needs
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// approve-drainer, real-safe holdout: bounded approve-and-revoke via Solady SafeTransferLib.
    function test_approveDrainer_soladySafeTransferLib_blocked() public {
        SoladyTokenFixture token = new SoladyTokenFixture();
        SoladySafeTransferLibWallet wallet = new SoladySafeTransferLibWallet();
        token.mint(address(wallet), START_BALANCE);

        // Bounded authorization: the wallet grants EXACTLY the action amount via the real
        // Solady safeApprove (never type(uint256).max).
        wallet.scopedApprove(address(token), ATTACKER, ACTION_AMOUNT);
        assertEq(token.allowance(address(wallet), ATTACKER), ACTION_AMOUNT, "bounded allowance set");

        // Guard: the authority is REAL - the spender can move up to the bounded amount.
        vm.prank(ATTACKER);
        token.transferFrom(address(wallet), ATTACKER, ACTION_AMOUNT);
        assertEq(token.balanceOf(ATTACKER), ACTION_AMOUNT, "bounded spend should succeed");

        // Vector (1/2): pulling the remaining full balance must revert (real ERC-20 allowance
        // accounting - the bounded allowance is exhausted).
        uint256 remaining = token.balanceOf(address(wallet));
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady ERC20: InsufficientAllowance
        token.transferFrom(address(wallet), ATTACKER, remaining);

        // Vector (2/2): after the interaction the wallet revokes -> no lingering drain surface.
        wallet.revoke(address(token), ATTACKER);
        assertEq(token.allowance(address(wallet), ATTACKER), 0, "allowance revoked to zero");

        // A post-revoke pull of anything also reverts (allowance is 0).
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.transferFrom(address(wallet), ATTACKER, 1);

        bool drained = (token.balanceOf(address(wallet)) < remaining);
        _report("solady-safetransferlib-safe", drained);

        assertFalse(drained, "real-safe SafeTransferLib wallet must not be drainable beyond the bound");
        assertEq(token.balanceOf(address(wallet)), remaining, "wallet balance must stay intact");
    }
}
