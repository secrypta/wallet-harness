// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OzScopedERC1155} from "../fixtures/set-approval-for-all/c-safe-impl/OzERC1155Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT for set-approval-for-all: OpenZeppelin `ERC1155`.
/// @notice The operator-for-all authorization is unmodified OZ v5.1.0 `ERC1155`. When the holder
///         has NOT granted `setApprovalForAll` to an attacker, the attacker's attempt to sweep
///         the holder's whole balance via `safeTransferFrom` / `safeBatchTransferFrom` reverts in
///         OZ's own check -> nothing leaves, so the harness must stay silent (BLOCKED, label
///         safe). A guard proves that a holder-authorized (approved) operator CAN transfer, so
///         BLOCKED is a real authorization rejection, not a broken token. Verdict from the real
///         outcome.
contract RealSafeOzERC1155HoldoutTest is Test {
    address constant HOLDER = address(0x401DE5); // the token holder
    address constant ATTACKER = address(0xA77ACC);
    address constant TRUSTED = address(0x7405732D); // holder-approved operator (guard)

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[set-approval-for-all] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    uint256 constant ID1 = 1;
    uint256 constant ID2 = 2;
    uint256 constant AMT = 100;

    function _mintCollection(OzScopedERC1155 t, address to) internal {
        t.mint(to, ID1, AMT);
        t.mint(to, ID2, AMT);
    }

    /// Protected (c): an un-approved operator cannot sweep the holder's balance.
    function test_setApprovalForAll_ozErc1155_blocked() public {
        address holder = HOLDER;
        OzScopedERC1155 token = new OzScopedERC1155();
        _mintCollection(token, holder);

        // The holder has NOT granted setApprovalForAll to the attacker.
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = ID1; ids[1] = ID2; amounts[0] = AMT; amounts[1] = AMT;

        vm.prank(ATTACKER);
        try token.safeBatchTransferFrom(holder, ATTACKER, ids, amounts, "") {} catch {}

        bool drained = (token.balanceOf(holder, ID1) < AMT || token.balanceOf(holder, ID2) < AMT);
        _report("oz-erc1155-safe", drained);

        assertFalse(drained, "un-approved operator must not sweep the holder's balance");
        assertEq(token.balanceOf(ATTACKER, ID1), 0, "attacker gets nothing (id1)");
        assertEq(token.balanceOf(ATTACKER, ID2), 0, "attacker gets nothing (id2)");
    }

    /// Guard: a holder-approved operator CAN transfer - BLOCKED above is a real auth rejection.
    function test_guard_approvedOperator_canTransfer() public {
        address holder = HOLDER;
        OzScopedERC1155 token = new OzScopedERC1155();
        _mintCollection(token, holder);

        vm.prank(holder);
        token.setApprovalForAll(TRUSTED, true);

        vm.prank(TRUSTED);
        token.safeTransferFrom(holder, TRUSTED, ID1, AMT, "");

        assertEq(token.balanceOf(TRUSTED, ID1), AMT, "approved operator should transfer");
        assertEq(token.balanceOf(holder, ID1), 0, "holder sent the approved id");
    }
}
