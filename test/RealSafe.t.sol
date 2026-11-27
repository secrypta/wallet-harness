// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OZERC20Fixture} from "../fixtures/approve-drainer/c-safe-impl/OZERC20Fixture.sol";
import {SafeAllowanceFlow} from "../fixtures/approve-drainer/c-safe-impl/SafeAllowanceFlow.sol";
import {OZERC721Fixture} from "../fixtures/set-approval-for-all/c-safe-impl/OZERC721Fixture.sol";
import {SafeOperatorFlow} from "../fixtures/set-approval-for-all/c-safe-impl/SafeOperatorFlow.sol";

/// @title Tier-(c) real-safe fixtures proof: drains revert against REAL OpenZeppelin.
/// @notice These are not toy guards: the allowance / operator-for-all authorization that
///         stops each drain is the unmodified OZ v5.1.0 implementation. The harness MUST
///         stay silent here (verdict BLOCKED, label safe) - this is the honest
///         0-false-positives test on genuinely-safe real code.
contract RealSafeTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18;
    uint256 constant ACTION_TOKEN = 1;
    uint256 constant COLLECTION_SIZE = 5;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory vector, string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[", vector, "] target=", target, " verdict=", verdict));
    }

    /// approve-drainer, real-safe: OZ ERC20 + bounded approve. Full-balance drain reverts.
    function test_approveDrainer_realSafe_blocked() public {
        OZERC20Fixture token = new OZERC20Fixture();
        SafeAllowanceFlow wallet = new SafeAllowanceFlow();
        token.mint(address(wallet), START_BALANCE);

        // bounded authorization: exactly the action amount
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

        bool drained = (token.balanceOf(address(wallet)) < remaining);
        _report("approve-drainer", "oz-safe-wallet", drained);

        assertFalse(drained, "real-safe OZ wallet must not be drainable beyond the bound");
        assertEq(token.balanceOf(address(wallet)), remaining, "balance must stay intact");
    }

    /// set-approval-for-all, real-safe: OZ ERC721 + scoped approve. Sweep of others reverts.
    function test_setApprovalForAll_realSafe_blocked() public {
        OZERC721Fixture token = new OZERC721Fixture();
        SafeOperatorFlow wallet = new SafeOperatorFlow();
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            token.mint(address(wallet), i);
        }

        // scoped authorization: exactly the one action token
        wallet.authorizeOperator(address(token), ATTACKER, ACTION_TOKEN);

        // Guard: the authority is REAL - the operator can move the scoped token.
        vm.prank(ATTACKER);
        token.transferFrom(address(wallet), ATTACKER, ACTION_TOKEN);
        assertEq(token.ownerOf(ACTION_TOKEN), ATTACKER, "scoped token should be movable");

        // Vector: sweeping any OTHER token must revert (OZ authorization check).
        uint256 lost = 0;
        for (uint256 i = 2; i <= COLLECTION_SIZE; i++) {
            vm.prank(ATTACKER);
            try token.transferFrom(address(wallet), ATTACKER, i) {
                lost++; // would mean a false authorization
            } catch {
                // expected: ERC721InsufficientApproval
            }
        }

        bool drained = (lost > 0);
        _report("set-approval-for-all", "oz-safe-operator", drained);

        assertFalse(drained, "real-safe OZ wallet must not lose non-scoped tokens");
        for (uint256 i = 2; i <= COLLECTION_SIZE; i++) {
            assertEq(token.ownerOf(i), address(wallet), "non-scoped token must stay with wallet");
        }
    }
}
