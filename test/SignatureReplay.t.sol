// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ReplaySettlement} from "../src/ReplaySettlement.sol";
import {BoundSettlement} from "../src/BoundSettlement.sol";

/// @title Signature-missing-deadline/nonce/domain vector (R5), proven by test body.
/// @notice The victim signs exactly ONE payment order to a counterparty and has approved a
///         settlement contract (as users of signed-order systems do). The drain comes from
///         whether that signature is BOUND to a single use. Against the vulnerable verifier
///         (bare hash: no domain, no nonce, no deadline) a relayer replays the one signature
///         until the owner is emptied. Against the bound verifier (EIP-712 domain + nonce +
///         deadline) the first settle consumes the nonce and every replay reverts, so the
///         owner pays exactly the one order they signed. The probe measures the real on-chain
///         outcome; the harness reads the "[signature-phishing] target=... verdict=..." lines.
contract SignatureReplayTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // the single payment the owner signs
    uint256 constant REPLAYS = START_BALANCE / ACTION_AMOUNT; // 10 replays empty the owner
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);
    address constant COUNTERPARTY = address(0xC0FFEE); // legit payee in the signed order

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// Vulnerable target: the owner's single signature over a bare, unbound hash is replayed
    /// by the relayer REPLAYS times, draining the owner completely.
    function test_vulnerableTarget_isDrained() public {
        MockERC20 token = new MockERC20();
        ReplaySettlement settlement = new ReplaySettlement();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        // Owner signs ONE order: pay ACTION_AMOUNT to the counterparty.
        bytes32 digest = settlement.hashOrder(owner, address(token), ACTION_AMOUNT, COUNTERPARTY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        // Relayer replays the SAME signature until the owner is drained.
        for (uint256 i = 0; i < REPLAYS; i++) {
            vm.prank(ATTACKER);
            settlement.settle(owner, address(token), ACTION_AMOUNT, COUNTERPARTY, v, r, s);
        }

        uint256 finalBalance = token.balanceOf(owner);
        bool drained = (finalBalance == 0);
        _report("replayable-sig", drained);

        assertTrue(drained, "vulnerable owner was not drained by replay");
        assertEq(finalBalance, 0, "replay should empty the owner");
        assertEq(token.balanceOf(COUNTERPARTY), START_BALANCE, "every replayed payment settled");
    }

    /// Protected target: the same replay attack against the bound verifier settles only the
    /// one signed order (first call), then every replay reverts on the consumed nonce. The
    /// owner keeps everything but the single payment they authorized. The harness MUST stay
    /// silent (0 false positives).
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        BoundSettlement settlement = new BoundSettlement();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        BoundSettlement.Order memory order = BoundSettlement.Order({
            owner: owner,
            token: address(token),
            amount: ACTION_AMOUNT,
            recipient: COUNTERPARTY,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, settlement.hashOrder(order));

        // Same replay loop as the vulnerable case: first settle succeeds, the rest revert.
        uint256 settledCount;
        for (uint256 i = 0; i < REPLAYS; i++) {
            vm.prank(ATTACKER);
            try settlement.settle(order, v, r, s) {
                settledCount++;
            } catch {}
        }

        uint256 finalBalance = token.balanceOf(owner);
        bool drained = (finalBalance == 0);
        _report("bound-sig-safe", drained);

        assertFalse(drained, "bound verifier should not be drainable by replay");
        assertEq(settledCount, 1, "only the one signed order should settle");
        assertEq(finalBalance, START_BALANCE - ACTION_AMOUNT, "owner pays exactly the signed order");
        assertEq(token.balanceOf(COUNTERPARTY), ACTION_AMOUNT, "counterparty receives the single payment");
    }

    /// Guard: the second replay against the bound verifier reverts specifically on the
    /// consumed nonce, so "BLOCKED" is the binding working - not a broken signature.
    function test_guard_boundReplay_revertsOnNonce() public {
        MockERC20 token = new MockERC20();
        BoundSettlement settlement = new BoundSettlement();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);
        vm.prank(owner);
        token.approve(address(settlement), type(uint256).max);

        BoundSettlement.Order memory order = BoundSettlement.Order({
            owner: owner,
            token: address(token),
            amount: ACTION_AMOUNT,
            recipient: COUNTERPARTY,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, settlement.hashOrder(order));

        vm.prank(ATTACKER);
        settlement.settle(order, v, r, s); // first use consumes nonce 0

        vm.prank(ATTACKER);
        vm.expectRevert(bytes("BoundSettlement: bad nonce"));
        settlement.settle(order, v, r, s); // replay rejected
    }
}
