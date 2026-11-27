// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyTokenFixture} from "../fixtures/approve-drainer/c-safe-impl/SoladyERC20Fixture.sol";
import {SoladyVaultFixture} from
    "../fixtures/approve-drainer/c-safe-impl/solady-erc4626-safe/SoladyVaultFixture.sol";
import {SoladyERC6909Fixture} from
    "../fixtures/approve-drainer/c-safe-impl/solady-erc6909-safe/SoladyERC6909Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT (approve-drainer): bounded approvals on two independent
///        Solady token standards - ERC-4626 vault shares and ERC-6909 multi-token.
/// @notice The allowance accounting that stops each over-draw is Solady's unmodified code
///         (independent of OpenZeppelin, never tuned against). split=holdout: the harness MUST
///         stay silent (verdict BLOCKED, label safe); a false positive here is a real result.
contract RealSafeSoladyApproveRound5HoldoutTest is Test {
    uint256 constant START = 100e18;
    uint256 constant ACTION = 10e18;
    address constant HOLDER = address(0xB0B);
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// approve-drainer, real-safe holdout: bounded approve on Solady ERC-4626 vault shares.
    function test_approveDrainer_soladyErc4626_blocked() public {
        SoladyTokenFixture asset = new SoladyTokenFixture();
        SoladyVaultFixture vault = new SoladyVaultFixture(address(asset));
        asset.mint(HOLDER, START);

        // Holder deposits assets and receives vault SHARES (themselves an ERC-20).
        vm.startPrank(HOLDER);
        asset.approve(address(vault), START);
        vault.deposit(START, HOLDER);
        vm.stopPrank();
        uint256 shares = vault.balanceOf(HOLDER);
        assertGt(shares, ACTION, "holder funded with shares");

        // Bounded share allowance.
        vm.prank(HOLDER);
        vault.approve(ATTACKER, ACTION);

        // Guard: the authority is REAL - the spender can move exactly the bounded shares.
        vm.prank(ATTACKER);
        vault.transferFrom(HOLDER, ATTACKER, ACTION);
        assertEq(vault.balanceOf(ATTACKER), ACTION, "bounded share spend should succeed");

        // Vector: pulling the full remaining share balance must revert (Solady allowance check).
        uint256 remaining = vault.balanceOf(HOLDER);
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady ERC20 (share token): InsufficientAllowance
        vault.transferFrom(HOLDER, ATTACKER, remaining);

        bool drained = (vault.balanceOf(HOLDER) < remaining);
        _report("solady-erc4626-safe", drained);
        assertFalse(drained, "real-safe Solady vault shares must not be drainable beyond the bound");
        assertEq(vault.balanceOf(HOLDER), remaining, "share balance intact");
    }

    /// approve-drainer, real-safe holdout: bounded per-id approve on Solady ERC-6909.
    function test_approveDrainer_soladyErc6909_blocked() public {
        SoladyERC6909Fixture token = new SoladyERC6909Fixture();
        uint256 id = 1;
        token.mint(HOLDER, id, START);

        // Bounded per-token-id allowance (not an operator grant, not max).
        vm.prank(HOLDER);
        token.approve(ATTACKER, id, ACTION);

        // Guard: the authority is REAL - the spender can move exactly the bounded amount.
        vm.prank(ATTACKER);
        token.transferFrom(HOLDER, ATTACKER, id, ACTION);
        assertEq(token.balanceOf(ATTACKER, id), ACTION, "bounded id spend should succeed");

        // Vector: pulling the full remaining id balance must revert (ERC6909 InsufficientPermission).
        uint256 remaining = token.balanceOf(HOLDER, id);
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady ERC6909: InsufficientPermission
        token.transferFrom(HOLDER, ATTACKER, id, remaining);

        bool drained = (token.balanceOf(HOLDER, id) < remaining);
        _report("solady-erc6909-safe", drained);
        assertFalse(drained, "real-safe Solady ERC6909 must not be drainable beyond the per-id bound");
        assertEq(token.balanceOf(HOLDER, id), remaining, "id balance intact");
    }
}
