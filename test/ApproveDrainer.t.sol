// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {MaliciousSpender} from "../src/MaliciousSpender.sol";
import {VulnerableWallet} from "../src/VulnerableWallet.sol";
import {SafeWallet} from "../src/SafeWallet.sol";

/// @title Approve-drainer vector, proven by test body.
/// @notice The flow is identical for both targets - a wallet authorizes a spender for
///         a small action, then a malicious spender tries to pull the FULL balance.
///         The only difference is the wallet's approval policy. The probe measures the
///         real on-chain outcome and derives the verdict (VULNERABLE / BLOCKED) from it;
///         the harness (harness/run.sh) reads these verdict lines from the forge output.
contract ApproveDrainerTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what the legit interaction actually needs
    address constant ATTACKER = address(0xA77ACC);

    /// @dev Runs the full approve-drainer flow against one wallet policy and returns
    ///      whether the malicious spender managed to empty the wallet.
    function _runVector(bool safePolicy) internal returns (bool drained, uint256 finalBalance) {
        MockERC20 token = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();

        address wallet;
        if (safePolicy) {
            wallet = address(new SafeWallet());
            token.mint(wallet, START_BALANCE);
            SafeWallet(wallet).authorizeSpender(address(token), address(spender), ACTION_AMOUNT);
        } else {
            wallet = address(new VulnerableWallet());
            token.mint(wallet, START_BALANCE);
            VulnerableWallet(wallet).authorizeSpender(address(token), address(spender), ACTION_AMOUNT);
        }

        uint256 balanceBefore = token.balanceOf(wallet);

        // Anyone can trigger the drain once the approval exists; model it as the attacker.
        vm.prank(ATTACKER);
        try spender.drain(address(token), wallet) {
            // drain succeeded; see how much is left
        } catch {
            // drain reverted (allowance too small): nothing was taken
        }

        finalBalance = token.balanceOf(wallet);
        drained = (balanceBefore > 0 && finalBalance == 0);
    }

    function _report(string memory target, bool drained) internal pure returns (string memory verdict) {
        verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(
            string.concat("[approve-drainer] target=", target, " verdict=", verdict)
        );
    }

    /// Vulnerable target: unlimited approve lets the spender take 100% of the balance.
    /// The harness MUST catch the vector here.
    function test_vulnerableTarget_isDrained() public {
        (bool drained, uint256 finalBalance) = _runVector(false);
        _report("vulnerable-wallet", drained);

        assertTrue(drained, "vulnerable target was not drained");
        assertEq(finalBalance, 0, "vulnerable wallet should be emptied");
    }

    /// Protected target: exact-amount approve makes the full-balance drain revert.
    /// The harness MUST stay silent here (0 false positives): verdict is BLOCKED and
    /// the balance is fully intact.
    function test_protectedTarget_isBlocked() public {
        (bool drained, uint256 finalBalance) = _runVector(true);
        _report("safe-wallet", drained);

        assertFalse(drained, "protected target should not be drainable");
        assertEq(finalBalance, START_BALANCE, "protected wallet balance must stay intact");
    }
}
