// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {GiftToken} from "../src/GiftToken.sol";
import {MaliciousSpender} from "../src/MaliciousSpender.sol";

/// @title Fake-airdrop vector (scam-token bait), proven by test body.
/// @notice An unsolicited GiftToken lands in the victim's wallet and lures them into a
///         "claim" flow. The claim never touches the gift - it grants an allowance on the
///         victim's REAL asset (MockERC20). The attacker then drains the real asset while
///         the worthless gift stays put. The distinct signal is the mismatch: the lure
///         (gift) is not the approval target (real asset).
///         The probe measures the real on-chain outcome and derives the verdict; the
///         harness reads the "[fake-airdrop] target=... verdict=..." lines.
contract FakeAirdropTest is Test {
    uint256 constant REAL_BALANCE = 100e18;
    uint256 constant GIFT_BALANCE = 5000e18; // minted by GiftToken's constructor
    address constant VICTIM = address(0xA14D409);
    address constant ATTACKER = address(0xA77ACC);

    struct Outcome {
        bool realDrained; // attacker emptied the victim's real asset
        uint256 finalReal; // victim's remaining real-asset balance
        uint256 attackerReal; // real asset that ended up with the attacker's spender
        uint256 finalGift; // victim's remaining gift balance (should be untouched)
    }

    /// @dev Runs the full fake-airdrop flow for one claim policy.
    function _runVector(bool safePolicy) internal returns (Outcome memory o) {
        MockERC20 realToken = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();
        // Unsolicited gift is dropped straight onto the victim - no action by them.
        GiftToken gift = new GiftToken(VICTIM);
        realToken.mint(VICTIM, REAL_BALANCE);

        // "Claim your reward" - in reality an allowance grant on the REAL asset, not the gift.
        // Unsafe: unlimited allowance on the real asset -> fully drainable.
        // Safe: claim grants no drainable allowance on the real asset (here: zero).
        vm.prank(VICTIM);
        realToken.approve(address(spender), safePolicy ? 0 : type(uint256).max);

        uint256 realBefore = realToken.balanceOf(VICTIM);
        vm.prank(ATTACKER);
        try spender.drain(address(realToken), VICTIM) {
            // drain succeeded
        } catch {
            // drain reverted (no drainable allowance on the real asset)
        }

        o.finalReal = realToken.balanceOf(VICTIM);
        o.attackerReal = realToken.balanceOf(address(spender));
        o.finalGift = gift.balanceOf(VICTIM);
        o.realDrained = (realBefore > 0 && o.finalReal == 0);
    }

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[fake-airdrop] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Vulnerable target: the claim grants unlimited allowance on the real asset, so the
    /// attacker drains 100% of it; the gift bait is left untouched.
    function test_vulnerableTarget_isDrained() public {
        Outcome memory o = _runVector(false);
        _report("vulnerable-claim", o.realDrained);

        assertTrue(o.realDrained, "real asset was not drained");
        assertEq(o.finalReal, 0, "victim's real asset should be emptied");
        assertEq(o.attackerReal, REAL_BALANCE, "attacker should hold the drained real asset");
        assertEq(o.finalGift, GIFT_BALANCE, "gift bait must stay untouched");
    }

    /// Protected target: the claim grants no drainable allowance on the real asset, so the
    /// full-balance drain reverts; the real asset (and the gift) stay intact.
    function test_protectedTarget_isBlocked() public {
        Outcome memory o = _runVector(true);
        _report("safe-claim", o.realDrained);

        assertFalse(o.realDrained, "real asset should not be drainable");
        assertEq(o.finalReal, REAL_BALANCE, "victim's real asset must stay intact");
        assertEq(o.attackerReal, 0, "attacker should get nothing");
        assertEq(o.finalGift, GIFT_BALANCE, "gift bait must stay untouched");
    }
}
