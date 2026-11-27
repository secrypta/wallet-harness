// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ResidualSpender} from "../src/ResidualSpender.sol";
import {LingeringAllowanceWallet} from "../src/LingeringAllowanceWallet.sol";
import {ResetAllowanceWallet} from "../src/ResetAllowanceWallet.sol";

/// @title Lingering-allowance vector (R3), proven by test body.
/// @notice Both wallets approve a service for an action amount and let it perform an action
///         that spends only PART of it. The only difference is the wallet's post-action
///         policy: the vulnerable wallet leaves the unused allowance lingering; the safe
///         wallet resets it to zero. A later sweep of the residual allowance drains the
///         vulnerable wallet and finds nothing on the safe one. The probe measures the real
///         on-chain outcome and derives the verdict (VULNERABLE / BLOCKED); the harness reads
///         the "[approve-drainer] target=... verdict=..." lines.
contract LingeringAllowanceTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // allowance granted for the action
    uint256 constant ACTION_SPEND = 4e18; // what the action actually consumes
    uint256 constant RESIDUAL = ACTION_AMOUNT - ACTION_SPEND; // 6e18 left lingering
    address constant ATTACKER = address(0xA77ACC);

    /// @dev Runs the full lingering-allowance flow for one wallet policy and returns the
    ///      residual the attacker managed to sweep plus the final balances.
    function _runVector(bool safePolicy)
        internal
        returns (uint256 swept, uint256 walletBalance, uint256 attackerBalance)
    {
        MockERC20 token = new MockERC20();
        ResidualSpender spender = new ResidualSpender();

        address wallet;
        if (safePolicy) {
            wallet = address(new ResetAllowanceWallet());
            token.mint(wallet, START_BALANCE);
            ResetAllowanceWallet(wallet).authorizeAndAct(address(token), address(spender), ACTION_AMOUNT, ACTION_SPEND);
        } else {
            wallet = address(new LingeringAllowanceWallet());
            token.mint(wallet, START_BALANCE);
            LingeringAllowanceWallet(wallet).authorizeAndAct(
                address(token), address(spender), ACTION_AMOUNT, ACTION_SPEND
            );
        }

        // Anyone can trigger the residual sweep once a lingering allowance exists.
        vm.prank(ATTACKER);
        try spender.sweepResidual(address(token), wallet, ATTACKER) returns (uint256 amount) {
            swept = amount;
        } catch {
            swept = 0;
        }

        walletBalance = token.balanceOf(wallet);
        attackerBalance = token.balanceOf(ATTACKER);
    }

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// Vulnerable target: the unused allowance lingers and is swept by the attacker.
    /// The harness MUST catch the vector here.
    function test_vulnerableTarget_isDrained() public {
        (uint256 swept, uint256 walletBalance, uint256 attackerBalance) = _runVector(false);
        bool drained = (swept > 0);
        _report("lingering-approve", drained);

        assertTrue(drained, "lingering residual was not swept");
        assertEq(swept, RESIDUAL, "attacker should sweep the full lingering residual");
        assertEq(attackerBalance, RESIDUAL, "attacker should hold the swept residual");
        // wallet lost the legit action spend AND the lingering residual.
        assertEq(walletBalance, START_BALANCE - ACTION_SPEND - RESIDUAL, "wallet drained beyond the action");
    }

    /// Protected target: the residual allowance was reset to zero, so the sweep takes
    /// nothing. The harness MUST stay silent here (0 false positives).
    function test_protectedTarget_isBlocked() public {
        (uint256 swept, uint256 walletBalance, uint256 attackerBalance) = _runVector(true);
        bool drained = (swept > 0);
        _report("reset-approve-safe", drained);

        assertFalse(drained, "reset wallet should have no lingering residual");
        assertEq(swept, 0, "nothing should be sweepable after reset");
        assertEq(attackerBalance, 0, "attacker should get nothing");
        // only the legit action spend left the wallet; the rest stays intact.
        assertEq(walletBalance, START_BALANCE - ACTION_SPEND, "safe wallet keeps everything but the action spend");
    }

    /// Guard: the legit action genuinely moved ACTION_SPEND to the merchant in the safe
    /// case, so "BLOCKED" means the residual was reset - not that the action never ran.
    function test_guard_legitActionSettled() public {
        MockERC20 token = new MockERC20();
        ResidualSpender spender = new ResidualSpender();
        address wallet = address(new ResetAllowanceWallet());
        token.mint(wallet, START_BALANCE);
        ResetAllowanceWallet(wallet).authorizeAndAct(address(token), address(spender), ACTION_AMOUNT, ACTION_SPEND);

        assertEq(token.balanceOf(spender.MERCHANT()), ACTION_SPEND, "legit action should pay the merchant");
        assertEq(token.allowance(wallet, address(spender)), 0, "safe wallet must leave zero residual allowance");
    }
}
