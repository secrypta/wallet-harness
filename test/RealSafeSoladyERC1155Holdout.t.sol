// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyMultiTokenFixture} from
    "../fixtures/set-approval-for-all/c-safe-impl/SoladyERC1155Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT: an un-approved operator sweep reverts against Solady ERC1155.
/// @notice Solady (Vectorized/solady, MIT) is an independent ERC-1155 implementation the wal
///         detectors were NEVER tuned against. This is the honest PRECISION test on unseen safe
///         code for the set-approval-for-all vector: without an `setApprovalForAll` grant, an
///         operator must NOT be able to move the holder's tokens, so the harness MUST stay silent
///         (verdict BLOCKED, label safe). A false positive here would be a real, recorded result.
///
///         split=holdout. The operator-for-all authorization that stops the sweep is Solady's
///         unmodified code, not a tweaked toy. A guard proves the authorization is REAL (an
///         explicitly approved operator CAN move the tokens), so BLOCKED is a genuine rejection.
contract RealSafeSoladyERC1155HoldoutTest is Test {
    uint256 constant TOKEN_ID = 7;
    uint256 constant HOLDER_BALANCE = 100;
    address constant HOLDER = address(0xB0B);
    address constant ATTACKER = address(0xA77ACC);
    address constant AUTHORIZED_OP = address(0x0F);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_setApprovalForAll_soladyErc1155_blocked() public {
        SoladyMultiTokenFixture token = new SoladyMultiTokenFixture();
        token.mint(HOLDER, TOKEN_ID, HOLDER_BALANCE);

        // Vector: the holder never approved ATTACKER; a sweep by the un-approved operator must revert.
        uint256 swept = 0;
        vm.prank(ATTACKER);
        try token.safeTransferFrom(HOLDER, ATTACKER, TOKEN_ID, HOLDER_BALANCE, "") {
            swept = token.balanceOf(ATTACKER, TOKEN_ID); // would mean a false authorization
        } catch {
            // expected: Solady ERC1155 NotOwnerNorApproved
        }

        bool drained = (swept > 0);
        _report("solady-erc1155-safe", drained);

        assertFalse(drained, "un-approved operator must not move the holder's ERC-1155 balance");
        assertEq(token.balanceOf(HOLDER, TOKEN_ID), HOLDER_BALANCE, "holder balance intact");
        assertEq(token.balanceOf(ATTACKER, TOKEN_ID), 0, "attacker gets nothing");
    }

    /// Guard: an explicitly approved operator DOES move the tokens - so BLOCKED above is a real
    /// rejection of an un-approved operator, not broken transfer logic.
    function test_guard_approvedOperator_canMove() public {
        SoladyMultiTokenFixture token = new SoladyMultiTokenFixture();
        token.mint(HOLDER, TOKEN_ID, HOLDER_BALANCE);

        vm.prank(HOLDER);
        token.setApprovalForAll(AUTHORIZED_OP, true);

        vm.prank(AUTHORIZED_OP);
        token.safeTransferFrom(HOLDER, AUTHORIZED_OP, TOKEN_ID, 10, "");

        assertEq(token.balanceOf(AUTHORIZED_OP, TOKEN_ID), 10, "approved operator should move tokens");
        assertEq(token.balanceOf(HOLDER, TOKEN_ID), HOLDER_BALANCE - 10, "only the moved amount left");
    }
}
