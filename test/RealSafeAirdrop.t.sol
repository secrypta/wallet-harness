// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OZRealAsset} from "../fixtures/fake-airdrop/c-safe-impl/OZRealAsset.sol";
import {GiftToken} from "../src/GiftToken.sol";
import {MaliciousSpender} from "../src/MaliciousSpender.sol";

/// @title fake-airdrop (c) real-safe fixture: genuine OpenZeppelin ERC-20.
/// @notice The 0-false-positive test on REAL code. The victim holds an unsolicited bait
///         token (GiftToken) plus a REAL asset that is a genuine, unmodified OpenZeppelin
///         v5.1.0 ERC20 (OZRealAsset). A safe claim flow grants NO drainable allowance on
///         the real asset, so the attacker's full-balance drain reverts on unmodified OZ
///         `_spendAllowance`; the real asset and the bait both stay intact. The harness must
///         stay silent here (label=safe -> BLOCKED). A guard shows OZ's allowance genuinely
///         gates (a bounded spend succeeds, a full drain reverts), so BLOCKED is not vacuous.
contract RealSafeAirdropTest is Test {
    uint256 constant REAL_BALANCE = 100e18;
    uint256 constant GIFT_BALANCE = 5000e18; // minted by GiftToken's constructor
    uint256 constant ACTION_AMOUNT = 10e18;
    address constant VICTIM = address(0xA14D409);
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[fake-airdrop] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Safe claim on real OZ code: no drainable allowance on the real asset -> full-balance
    /// drain reverts, real asset and bait intact -> BLOCKED.
    function test_ozSafeClaim_isBlocked() public {
        OZRealAsset real = new OZRealAsset();
        GiftToken gift = new GiftToken(VICTIM); // unsolicited bait lands on the victim
        MaliciousSpender spender = new MaliciousSpender();
        real.mint(VICTIM, REAL_BALANCE);

        // Safe claim: grants no drainable allowance on the real asset.
        vm.prank(VICTIM);
        real.approve(address(spender), 0);

        uint256 realBefore = real.balanceOf(VICTIM);
        vm.prank(ATTACKER);
        try spender.drain(address(real), VICTIM) {
            // drain succeeded
        } catch {
            // drain reverted (no drainable allowance) - expected on safe code
        }

        uint256 finalReal = real.balanceOf(VICTIM);
        bool drained = (realBefore > 0 && finalReal == 0);
        _report("oz-safe-claim", drained);

        assertFalse(drained, "real asset should not be drainable");
        assertEq(finalReal, REAL_BALANCE, "real asset must stay intact");
        assertEq(real.balanceOf(address(spender)), 0, "spender should get nothing");
        assertEq(gift.balanceOf(VICTIM), GIFT_BALANCE, "bait must stay untouched");
    }

    /// Guard: OZ's allowance genuinely gates, so the BLOCKED above means "the drain was
    /// stopped", not "the spender had no way to move anything". A bounded allowance lets the
    /// exact action amount move, while a full-balance transferFrom still reverts.
    function test_guard_ozAllowance_isReal() public {
        OZRealAsset real = new OZRealAsset();
        real.mint(VICTIM, REAL_BALANCE);

        vm.prank(VICTIM);
        real.approve(ATTACKER, ACTION_AMOUNT);

        // In scope: the attacker can move exactly the bounded amount.
        vm.prank(ATTACKER);
        real.transferFrom(VICTIM, ATTACKER, ACTION_AMOUNT);
        assertEq(real.balanceOf(VICTIM), REAL_BALANCE - ACTION_AMOUNT, "bounded spend should succeed");

        // Out of scope: a full-balance drain reverts (allowance now 0).
        uint256 fullBalance = real.balanceOf(VICTIM);
        vm.prank(ATTACKER);
        vm.expectRevert();
        real.transferFrom(VICTIM, ATTACKER, fullBalance);
    }
}
