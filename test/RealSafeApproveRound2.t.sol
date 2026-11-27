// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OZERC20Fixture} from "../fixtures/approve-drainer/c-safe-impl/OZERC20Fixture.sol";
import {SafeErc20AllowanceFlow} from "../fixtures/approve-drainer/c-safe-impl/SafeErc20AllowanceFlow.sol";
import {OZERC4626Fixture} from "../fixtures/approve-drainer/c-safe-impl/OZERC4626Fixture.sol";
import {IERC20} from "../fixtures/vendor/oz/token/ERC20/IERC20.sol";

/// @title Tier-(c) real-safe fixtures (round 2) proof: drains revert against REAL OpenZeppelin.
/// @notice Not toy guards: the allowance accounting that stops each drain is the unmodified OZ
///         v5.1.0 SafeERC20 / ERC20 / ERC4626. The harness MUST stay silent here (verdict
///         BLOCKED, label safe) - the honest 0-false-positives test on genuinely-safe real code.
contract RealSafeApproveRound2Test is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[approve-drainer] target=", target, " verdict=", verdict));
    }

    /// Real OZ SafeERC20.forceApprove bounded-approve + reset. Full-balance drain reverts.
    function test_approveDrainer_ozSafeErc20_blocked() public {
        OZERC20Fixture token = new OZERC20Fixture();
        SafeErc20AllowanceFlow wallet = new SafeErc20AllowanceFlow();
        token.mint(address(wallet), START_BALANCE);

        // bounded authorization via real OZ SafeERC20.forceApprove: exactly the action amount
        wallet.authorizeSpender(address(token), ATTACKER, ACTION_AMOUNT);

        // Guard: the authority is REAL - the spender can move up to the bounded amount.
        vm.prank(ATTACKER);
        token.transferFrom(address(wallet), ATTACKER, ACTION_AMOUNT);
        assertEq(token.balanceOf(ATTACKER), ACTION_AMOUNT, "bounded spend should succeed");

        // Vector: pulling the remaining full balance must revert (OZ allowance check).
        uint256 remaining = token.balanceOf(address(wallet));
        vm.prank(ATTACKER);
        vm.expectRevert(); // OZ ERC20InsufficientAllowance
        token.transferFrom(address(wallet), ATTACKER, remaining);

        // And after the action the policy revokes any residual allowance to zero.
        wallet.revokeSpender(address(token), ATTACKER);
        assertEq(token.allowance(address(wallet), ATTACKER), 0, "residual allowance must be revoked");

        bool drained = (token.balanceOf(address(wallet)) < remaining);
        _report("oz-safeerc20-safe", drained);

        assertFalse(drained, "real-safe OZ SafeERC20 flow must not be drainable beyond the bound");
        assertEq(token.balanceOf(address(wallet)), remaining, "balance must stay intact");
    }

    /// Real OZ ERC4626 vault: bounded approve on SHARES. Full-balance share drain reverts.
    function test_approveDrainer_ozErc4626Shares_blocked() public {
        OZERC20Fixture asset = new OZERC20Fixture();
        OZERC4626Fixture vault = new OZERC4626Fixture(IERC20(address(asset)));
        address victim = address(0xBEEF);
        vault.mintShares(victim, START_BALANCE);

        // bounded approve on the real OZ vault share token: exactly the action amount
        vm.prank(victim);
        vault.approve(ATTACKER, ACTION_AMOUNT);

        // Guard: the authority is REAL - the spender can move up to the bounded share amount.
        vm.prank(ATTACKER);
        vault.transferFrom(victim, ATTACKER, ACTION_AMOUNT);
        assertEq(vault.balanceOf(ATTACKER), ACTION_AMOUNT, "bounded share spend should succeed");

        // Vector: pulling the remaining full share balance must revert (OZ allowance check).
        uint256 remaining = vault.balanceOf(victim);
        vm.prank(ATTACKER);
        vm.expectRevert(); // OZ ERC20InsufficientAllowance
        vault.transferFrom(victim, ATTACKER, remaining);

        bool drained = (vault.balanceOf(victim) < remaining);
        _report("oz-erc4626-safe", drained);

        assertFalse(drained, "real-safe OZ ERC4626 shares must not be drainable beyond the bound");
        assertEq(vault.balanceOf(victim), remaining, "share balance must stay intact");
    }
}
