// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {GuardedExecutor} from "../fixtures/delegatecall-hijack/c-safe-impl/GuardedExecutor.sol";
import {AccountTakeoverModule} from "../src/AccountTakeoverModule.sol";
import {AuditedLibModule} from "../src/AuditedLibModule.sol";

/// @title delegatecall-hijack tier (c): reference-impl guard + slot invariant.
/// @notice The canonical post-Bybit mitigation, defense-in-depth: (1) a transaction guard
///         allows delegatecall only to allow-listed audited libraries; (2) an
///         implementation-slot invariant reverts if slot 0 moved during execution. The same
///         Bybit-style delegatecall-swap payload is BLOCKED by (1); even if the target were
///         mistakenly allow-listed, (2) still rolls back the slot-0 takeover. Plain calls
///         and an allow-listed benign delegate still run, so BLOCKED is not vacuous. The
///         harness MUST stay silent here (verdict BLOCKED) - the honest 0-false-positive
///         test on the real defense.
contract RealSafeDelegatecallTest is Test {
    uint256 constant START_BALANCE = 100e18;
    address constant ATTACKER = address(0xA77ACC);
    address constant ORIG_IMPL = address(0x100C);
    address constant ACCOUNT_OWNER = address(0x0E);

    function _report(string memory target, bool hijacked) internal pure {
        string memory verdict = hijacked ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[delegatecall-hijack] target=", target, " verdict=", verdict));
    }

    /// Guarded executor blocks the delegatecall-swap: layer (1) rejects the unknown target.
    function test_delegatecallHijack_guarded_blocked() public {
        MockERC20 token = new MockERC20();
        GuardedExecutor account = new GuardedExecutor(ORIG_IMPL, ACCOUNT_OWNER);
        AccountTakeoverModule module = new AccountTakeoverModule();
        token.mint(address(account), START_BALANCE);

        bytes memory data =
            abi.encodeWithSignature("hijack(address,address,address)", ATTACKER, address(token), ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(GuardedExecutor.DelegatecallToUntrusted.selector, address(module))
        );
        account.execTransaction(address(module), data, 1);

        bool implSwapped = (account.implementation() != ORIG_IMPL);
        bool drained = (token.balanceOf(address(account)) < START_BALANCE);
        bool hijacked = implSwapped || drained;
        _report("guarded-exec-safe", hijacked);

        assertFalse(hijacked, "guarded executor must block the delegatecall hijack");
        assertEq(account.implementation(), ORIG_IMPL, "logic pointer unchanged");
        assertEq(token.balanceOf(address(account)), START_BALANCE, "balance intact");
    }

    /// Layer (2) in isolation: even if the attacker module were (mistakenly) allow-listed,
    /// the implementation-slot invariant reverts the whole tx, rolling back BOTH the slot-0
    /// takeover and the sweep. Defense-in-depth proof.
    function test_slotInvariant_catchesAllowlistedHijack() public {
        MockERC20 token = new MockERC20();
        GuardedExecutor account = new GuardedExecutor(ORIG_IMPL, ACCOUNT_OWNER);
        AccountTakeoverModule module = new AccountTakeoverModule();
        token.mint(address(account), START_BALANCE);
        account.allowDelegate(address(module), true); // mistaken allow-list

        bytes memory data =
            abi.encodeWithSignature("hijack(address,address,address)", ATTACKER, address(token), ATTACKER);
        vm.expectRevert(); // ImplementationSlotChanged - invariant reverts after exec
        account.execTransaction(address(module), data, 1);

        assertEq(account.implementation(), ORIG_IMPL, "slot invariant rolled back the takeover");
        assertEq(token.balanceOf(address(account)), START_BALANCE, "sweep rolled back with the revert");
    }

    /// Guard A: a plain call (operation 0) still works.
    function test_guarded_plainCallWorks() public {
        MockERC20 token = new MockERC20();
        GuardedExecutor account = new GuardedExecutor(ORIG_IMPL, ACCOUNT_OWNER);
        token.mint(address(account), START_BALANCE);

        account.execTransaction(
            address(token), abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, 1e18), 0
        );
        assertEq(token.balanceOf(ATTACKER), 1e18, "normal call transfer must work");
    }

    /// Guard B: an allow-listed benign delegate still runs (guard restricts target, not op).
    function test_guarded_allowlistedDelegateRuns() public {
        GuardedExecutor account = new GuardedExecutor(ORIG_IMPL, ACCOUNT_OWNER);
        AuditedLibModule lib = new AuditedLibModule();
        account.allowDelegate(address(lib), true);

        account.execTransaction(address(lib), abi.encodeWithSignature("ping()"), 1); // succeeds
        assertEq(account.implementation(), ORIG_IMPL, "audited delegate leaves slot 0 intact");
    }
}
