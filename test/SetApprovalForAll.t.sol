// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC721} from "../src/MockERC721.sol";
import {MaliciousOperator} from "../src/MaliciousOperator.sol";
import {VulnerableWalletNFT} from "../src/VulnerableWalletNFT.sol";
import {SafeWalletNFT} from "../src/SafeWalletNFT.sol";

/// @title set-approval-for-all vector, proven by test body.
/// @notice The flow is identical for both targets - a wallet authorizes an operator for
///         ONE token it needs handled, then a malicious operator tries to sweep the
///         wallet's WHOLE collection. The only difference is the wallet's authorization
///         policy: blanket `setApprovalForAll` (vulnerable) vs scoped `approve` on the
///         single action token (safe).
///
///         Drain metric (the key to 0 false positives): a wallet is "drained" only if a
///         token OTHER than the one legitimately scoped leaves it. Moving the single
///         in-scope token is authorized by design and is NOT counted as a drain, so the
///         protected target is never falsely flagged.
contract SetApprovalForAllTest is Test {
    // The wallet owns a 5-token collection; the legit action concerns ACTION_TOKEN only.
    uint256 constant ACTION_TOKEN = 1;
    uint256 constant COLLECTION_SIZE = 5;
    address constant ATTACKER = address(0xA77ACC);

    /// @dev Mints the collection to `wallet` and returns [1..COLLECTION_SIZE].
    function _mintCollection(MockERC721 token, address wallet)
        internal
        returns (uint256[] memory ids)
    {
        ids = new uint256[](COLLECTION_SIZE);
        for (uint256 i = 0; i < COLLECTION_SIZE; i++) {
            uint256 id = i + 1;
            token.mint(wallet, id);
            ids[i] = id;
        }
    }

    /// @dev Counts how many of the victim's NON-scoped tokens the operator took, i.e.
    ///      tokens other than ACTION_TOKEN that no longer belong to the victim.
    function _unauthorizedLost(MockERC721 token, address victim, uint256[] memory ids)
        internal
        view
        returns (uint256 lost)
    {
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] == ACTION_TOKEN) continue;
            if (token.ownerOf(ids[i]) != victim) lost++;
        }
    }

    /// @dev Runs the full set-approval-for-all flow against one wallet policy.
    ///      Returns whether the operator drained any unauthorized token, and how many of
    ///      the victim's non-scoped tokens remain.
    function _runVector(bool safePolicy)
        internal
        returns (bool drained, uint256 nonScopedRemaining)
    {
        MockERC721 token = new MockERC721();
        MaliciousOperator operator = new MaliciousOperator();

        address wallet;
        if (safePolicy) {
            wallet = address(new SafeWalletNFT());
        } else {
            wallet = address(new VulnerableWalletNFT());
        }

        uint256[] memory ids = _mintCollection(token, wallet);

        // The wallet authorizes the operator for the ONE token the action needs.
        if (safePolicy) {
            SafeWalletNFT(wallet).authorizeOperator(address(token), address(operator), ACTION_TOKEN);
        } else {
            VulnerableWalletNFT(wallet).authorizeOperator(address(token), address(operator), ACTION_TOKEN);
        }

        // Anyone can trigger the sweep once the approval exists; model it as the attacker.
        // The operator tries to take the ENTIRE collection; unauthorized tokens revert
        // inside sweep() and are skipped.
        vm.prank(ATTACKER);
        operator.sweep(address(token), wallet, ids);

        uint256 lost = _unauthorizedLost(token, wallet, ids);
        drained = (lost > 0);

        // how many non-scoped tokens the victim still holds (COLLECTION_SIZE-1 if intact)
        nonScopedRemaining = (COLLECTION_SIZE - 1) - lost;
    }

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(
            string.concat("[set-approval-for-all] target=", target, " verdict=", verdict)
        );
    }

    /// Vulnerable target: blanket setApprovalForAll lets the operator sweep 100% of the
    /// collection. The harness MUST catch the vector here.
    function test_vulnerableTarget_isDrained() public {
        (bool drained, uint256 nonScopedRemaining) = _runVector(false);
        _report("vulnerable-wallet", drained);

        assertTrue(drained, "vulnerable target was not drained");
        assertEq(nonScopedRemaining, 0, "vulnerable wallet should lose every non-scoped token");
    }

    /// Protected target: per-token approve scopes the operator to ACTION_TOKEN only, so
    /// sweeping the rest reverts. The harness MUST stay silent here (0 false positives):
    /// verdict is BLOCKED and every non-scoped token stays with the victim. Moving the
    /// single in-scope token is authorized and is not treated as a drain.
    function test_protectedTarget_isBlocked() public {
        (bool drained, uint256 nonScopedRemaining) = _runVector(true);
        _report("safe-wallet", drained);

        assertFalse(drained, "protected target should not lose unauthorized tokens");
        assertEq(
            nonScopedRemaining,
            COLLECTION_SIZE - 1,
            "protected wallet must keep all non-scoped tokens"
        );
    }

    /// Guard: make BLOCKED mean "the vector was stopped", not "the operator had no
    /// authority at all". Proves the scoped approve is genuinely usable for its one
    /// token, so the protected verdict is not a false pass. A direct transferFrom of a
    /// NON-scoped token by the same operator must still revert.
    function test_protected_scopeIsRealAndTight() public {
        MockERC721 token = new MockERC721();
        MaliciousOperator operator = new MaliciousOperator();
        address wallet = address(new SafeWalletNFT());
        uint256[] memory ids = _mintCollection(token, wallet);

        SafeWalletNFT(wallet).authorizeOperator(address(token), address(operator), ACTION_TOKEN);

        // In scope: the operator can move ACTION_TOKEN (authority is real, not vacuous).
        vm.prank(address(operator));
        token.transferFrom(wallet, ATTACKER, ACTION_TOKEN);
        assertEq(token.ownerOf(ACTION_TOKEN), ATTACKER, "scoped token should be movable");

        // Out of scope: a different token must revert for the same operator.
        uint256 otherToken = ACTION_TOKEN + 1;
        vm.prank(address(operator));
        vm.expectRevert(bytes("ERC721: caller is not owner nor approved"));
        token.transferFrom(wallet, ATTACKER, otherToken);

        ids; // silence unused warning
    }
}
