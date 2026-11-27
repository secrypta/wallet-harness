// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OzERC721OperatorFixture} from
    "../fixtures/set-approval-for-all/c-safe-impl/OzERC721OperatorFixture.sol";

/// @title Tier-(c) real-safe HOLDOUT: a non-approved operator sweep reverts against OZ ERC721.
/// @notice OpenZeppelin v5.1.0 ERC721 operator-for-all authorization is real published code. An
///         operator the holder never granted `setApprovalForAll` to must NOT be able to move the
///         holder's tokens, so the harness MUST stay silent (verdict BLOCKED, label safe). A guard
///         confirms an operator the holder DID approve-for-all CAN move the tokens, so BLOCKED is a
///         real rejection, not broken transfer logic. split=holdout; verdict from the real outcome.
contract RealSafeOzERC721OperatorHoldoutTest is Test {
    uint256 constant COLLECTION_SIZE = 5;
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

    function test_setApprovalForAll_ozErc721_blocked() public {
        OzERC721OperatorFixture nft = new OzERC721OperatorFixture();
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            nft.mint(HOLDER, i);
        }

        // The holder never calls setApprovalForAll for ATTACKER; a sweep must revert on each token.
        uint256 lost = 0;
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            vm.prank(ATTACKER);
            try nft.transferFrom(HOLDER, ATTACKER, i) {
                lost++; // would mean a false authorization
            } catch {
                // expected: OZ ERC721InsufficientApproval
            }
        }

        bool drained = (lost > 0);
        _report("oz-erc721-operator-safe", drained);

        assertFalse(drained, "un-approved operator must not sweep the holder's ERC-721 tokens");
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            assertEq(nft.ownerOf(i), HOLDER, "every token must stay with the holder");
        }
    }

    /// Guard: an operator the holder approved-for-all DOES move the tokens - so BLOCKED above is a
    /// real rejection of an un-approved operator, not broken transfer logic.
    function test_guard_approvedOperator_canSweep() public {
        OzERC721OperatorFixture nft = new OzERC721OperatorFixture();
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            nft.mint(HOLDER, i);
        }

        vm.prank(HOLDER);
        nft.setApprovalForAll(AUTHORIZED_OP, true);

        vm.prank(AUTHORIZED_OP);
        nft.transferFrom(HOLDER, AUTHORIZED_OP, 1);
        assertEq(nft.ownerOf(1), AUTHORIZED_OP, "approved-for-all operator should move a token");
    }
}
