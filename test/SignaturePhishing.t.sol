// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {Settlement} from "../src/Settlement.sol";
import {MaliciousRelayer} from "../src/MaliciousRelayer.sol";

/// @title Signature-phishing vector (malicious order signature), proven by test body.
/// @notice The victim has approved a settlement contract (as marketplace users do); the
///         drain comes purely from WHICH order they are lured into signing. The vulnerable
///         victim blind-signs the attacker's all-asset order (opaque intent); the protected
///         victim signs only a decodable, scoped order to a known counterparty, so the
///         attacker's all-asset order - which the victim never signed - reverts on the
///         signature check. A guard test shows the scoped order is genuinely settleable, so
///         BLOCKED means "the malicious order was rejected", not "signatures don't work".
///         The probe measures the real on-chain outcome; the harness reads the
///         "[signature-phishing] target=... verdict=..." lines.
contract SignaturePhishingTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what a legit scoped order moves
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);
    address constant COUNTERPARTY = address(0xC0FFEE); // legit buyer in the scoped order

    function _sign(Settlement settlement, Settlement.Order memory o)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(OWNER_PK, settlement.hashOrder(o));
    }

    /// @dev Runs the full signature-phishing flow for one signing policy.
    function _runVector(bool safePolicy) internal returns (bool drained, uint256 finalBalance, uint256 attackerBalance) {
        MockERC20 token = new MockERC20();
        Settlement settlement = new Settlement();
        MaliciousRelayer relayer = new MaliciousRelayer();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        // Marketplace setup: the owner approves the settlement contract (legit, trusted infra).
        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        uint256 deadline = block.timestamp + 1 hours;
        // The attacker's goal order: move the whole balance to the attacker.
        Settlement.Order memory evilOrder = Settlement.Order({
            owner: owner,
            token: address(token),
            amount: START_BALANCE,
            recipient: ATTACKER,
            nonce: 0,
            deadline: deadline
        });

        if (!safePolicy) {
            // Vulnerable: victim blind-signs the attacker's all-asset order.
            (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, evilOrder);
            vm.prank(ATTACKER);
            try relayer.relay(settlement, evilOrder, v, r, s) {} catch {}
        } else {
            // Protected: victim signs only a decodable, scoped order to a known counterparty.
            Settlement.Order memory scoped = Settlement.Order({
                owner: owner,
                token: address(token),
                amount: ACTION_AMOUNT,
                recipient: COUNTERPARTY,
                nonce: 0,
                deadline: deadline
            });
            (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, scoped);
            // The attacker holds only the scoped signature; replaying it on the all-asset
            // order fails the signature check (different digest).
            vm.prank(ATTACKER);
            try relayer.relay(settlement, evilOrder, v, r, s) {} catch {}
        }

        finalBalance = token.balanceOf(owner);
        attackerBalance = token.balanceOf(ATTACKER);
        drained = (START_BALANCE > 0 && finalBalance == 0);
    }

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Vulnerable target: the blind-signed all-asset order settles 100% to the attacker.
    function test_vulnerableTarget_isDrained() public {
        (bool drained, uint256 finalBalance, uint256 attackerBalance) = _runVector(false);
        _report("vulnerable-sig", drained);

        assertTrue(drained, "vulnerable target was not drained");
        assertEq(finalBalance, 0, "vulnerable owner should be emptied");
        assertEq(attackerBalance, START_BALANCE, "attacker should hold the drained balance");
    }

    /// Protected target: the attacker's all-asset order was never signed, so it reverts;
    /// the owner's balance stays intact and the attacker gets nothing.
    function test_protectedTarget_isBlocked() public {
        (bool drained, uint256 finalBalance, uint256 attackerBalance) = _runVector(true);
        _report("safe-sig", drained);

        assertFalse(drained, "protected target should not be drainable");
        assertEq(finalBalance, START_BALANCE, "protected owner balance must stay intact");
        assertEq(attackerBalance, 0, "attacker should get nothing");
    }

    /// Guard: the scoped order the protected victim actually signed is genuinely settleable,
    /// so "BLOCKED" means the malicious order was rejected - not that signatures are broken.
    function test_guard_scopedOrder_isSettleable() public {
        MockERC20 token = new MockERC20();
        Settlement settlement = new Settlement();
        MaliciousRelayer relayer = new MaliciousRelayer();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);
        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        Settlement.Order memory scoped = Settlement.Order({
            owner: owner,
            token: address(token),
            amount: ACTION_AMOUNT,
            recipient: COUNTERPARTY,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, scoped);

        vm.prank(ATTACKER); // anyone can relay a validly signed order
        relayer.relay(settlement, scoped, v, r, s);

        assertEq(token.balanceOf(COUNTERPARTY), ACTION_AMOUNT, "scoped order should settle to counterparty");
        assertEq(token.balanceOf(owner), START_BALANCE - ACTION_AMOUNT, "only the scoped amount should move");
    }

    /// Guard: an expired order reverts (BLOCKED is never a stale-order accident).
    function test_guard_expiredOrder_reverts() public {
        MockERC20 token = new MockERC20();
        Settlement settlement = new Settlement();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);
        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        vm.warp(1_000);
        Settlement.Order memory o = Settlement.Order({
            owner: owner,
            token: address(token),
            amount: START_BALANCE,
            recipient: ATTACKER,
            nonce: 0,
            deadline: block.timestamp - 1
        });
        (uint8 v, bytes32 r, bytes32 s) = _sign(settlement, o);

        vm.prank(ATTACKER);
        vm.expectRevert(bytes("Settlement: order expired"));
        settlement.settle(o, v, r, s);
    }
}
