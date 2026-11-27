// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SafeSettlement} from "../src/SafeSettlement.sol";

/// @title Tier-(c) real-safe fixture proof for signature-phishing: scoped settlement on
///        REAL OpenZeppelin EIP712 + ECDSA.
/// @notice The signature verification is unmodified OZ (`EIP712` digest + `ECDSA.recover`).
///         The defensive policy accepts only a decodable, scoped order to an allow-listed
///         counterparty, so a phishing order - all-asset and/or to an untrusted attacker -
///         reverts here even with a valid signature. There is no blind-hash entrypoint. The
///         harness MUST stay silent (verdict BLOCKED, label safe): the honest
///         0-false-positives test on real signature-verification code.
contract RealSafeSignatureTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // scoped cap / what a legit order moves
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);
    address constant COUNTERPARTY = address(0xC0FFEE); // allow-listed legit buyer

    function _sign(SafeSettlement settlement, SafeSettlement.Order memory o)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(OWNER_PK, settlement.hashOrder(o));
    }

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[signature-phishing] target=", target, " verdict=", verdict));
    }

    function _setup()
        internal
        returns (MockERC20 token, SafeSettlement settlement, address owner)
    {
        token = new MockERC20();
        settlement = new SafeSettlement(ACTION_AMOUNT);
        owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);
        // Marketplace setup: owner approves the settlement (trusted infra).
        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);
        // Only the genuine counterparty is allow-listed.
        settlement.allowRecipient(COUNTERPARTY);
    }

    /// Protected (c): a phishing all-asset order to the attacker reverts on the scoped
    /// policy even though the owner signed it; assets stay intact.
    function test_signaturePhishing_realSafe_blocked() public {
        (MockERC20 token, SafeSettlement settlement, address owner) = _setup();

        // The attacker's goal order: whole balance to the attacker, validly signed by owner.
        SafeSettlement.Order memory evil = SafeSettlement.Order({
            owner: owner,
            token: address(token),
            amount: START_BALANCE,
            recipient: ATTACKER,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, evil);

        vm.prank(ATTACKER);
        try settlement.settle(evil, v, r, s) {
            // would mean the phishing order settled
        } catch {
            // expected: rejected by the scoped policy
        }

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("oz-sig-safe", drained);

        assertFalse(drained, "scoped settlement must not settle a phishing all-asset order");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: a genuine scoped order to the allow-listed counterparty is settleable, so the
    /// real OZ signature stack + policy work (BLOCKED is a real rejection, not broken sigs).
    function test_guard_scopedOrder_isSettleable() public {
        (MockERC20 token, SafeSettlement settlement, address owner) = _setup();

        SafeSettlement.Order memory scoped = SafeSettlement.Order({
            owner: owner,
            token: address(token),
            amount: ACTION_AMOUNT,
            recipient: COUNTERPARTY,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, scoped);

        vm.prank(ATTACKER); // anyone may relay a validly signed, in-policy order
        settlement.settle(scoped, v, r, s);

        assertEq(token.balanceOf(COUNTERPARTY), ACTION_AMOUNT, "scoped order should settle");
        assertEq(token.balanceOf(owner), START_BALANCE - ACTION_AMOUNT, "only the scoped amount moved");
    }

    /// Guard: an all-asset order even to the allow-listed counterparty exceeds the scoped
    /// cap and reverts - proving the cap, not just the allow-list, blocks all-asset drains.
    function test_guard_allAssetOrder_exceedsCap_reverts() public {
        (MockERC20 token, SafeSettlement settlement, address owner) = _setup();

        SafeSettlement.Order memory allAsset = SafeSettlement.Order({
            owner: owner,
            token: address(token),
            amount: START_BALANCE,
            recipient: COUNTERPARTY,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, allAsset);

        vm.prank(ATTACKER);
        vm.expectRevert(bytes("SafeSettlement: order exceeds scoped cap"));
        settlement.settle(allAsset, v, r, s);
    }
}
