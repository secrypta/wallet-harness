// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyNFTFixture} from "../fixtures/set-approval-for-all/c-safe-impl/SoladyERC721Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT: sweep of non-approved tokens reverts against Solady ERC721.
/// @notice Solady (Vectorized/solady, MIT) is an independent ERC-721 implementation the wal
///         detectors were NEVER tuned against. This is the honest PRECISION test on unseen safe
///         code for the set-approval-for-all vector: a scoped single-token approval must NOT let
///         an operator sweep the holder's other tokens, so the harness MUST stay silent (verdict
///         BLOCKED, label safe). A false positive here would be a real, recorded result.
///
///         split=holdout. The per-token authorization that stops the sweep is Solady's
///         unmodified code, not a tweaked toy.
contract RealSafeSoladyNFTHoldoutTest is Test {
    uint256 constant COLLECTION_SIZE = 5;
    uint256 constant SCOPED_TOKEN = 1;
    address constant HOLDER = address(0xB0B);
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory vector, string memory target, bool drained) internal pure {
        console.log(
            string.concat("[", vector, "] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_setApprovalForAll_soladySafe_blocked() public {
        SoladyNFTFixture nft = new SoladyNFTFixture();
        for (uint256 i = 1; i <= COLLECTION_SIZE; i++) {
            nft.mint(HOLDER, i);
        }

        // scoped authorization: exactly the one action token (NOT setApprovalForAll)
        vm.prank(HOLDER);
        nft.approve(ATTACKER, SCOPED_TOKEN);

        // Guard: the authority is REAL - the operator can move the scoped token.
        vm.prank(ATTACKER);
        nft.transferFrom(HOLDER, ATTACKER, SCOPED_TOKEN);
        assertEq(nft.ownerOf(SCOPED_TOKEN), ATTACKER, "scoped token should be movable");

        // Vector: sweeping any OTHER token must revert (Solady authorization check).
        uint256 lost = 0;
        for (uint256 i = 2; i <= COLLECTION_SIZE; i++) {
            vm.prank(ATTACKER);
            try nft.transferFrom(HOLDER, ATTACKER, i) {
                lost++; // would mean a false authorization
            } catch {
                // expected: Solady ERC721 NotOwnerNorApproved
            }
        }

        bool drained = (lost > 0);
        _report("set-approval-for-all", "solady-erc721-safe", drained);

        assertFalse(drained, "real-safe Solady NFT must not lose non-scoped tokens");
        for (uint256 i = 2; i <= COLLECTION_SIZE; i++) {
            assertEq(nft.ownerOf(i), HOLDER, "non-scoped token must stay with the holder");
        }
    }
}
