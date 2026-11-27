// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {
    DelegationSweeper,
    VulnerableDelegationAccount,
    SafeDelegationAccount
} from "../src/DelegationVector.sol";

/// @title eip7702-delegation vector (a-toy), proven by test body.
/// @notice A victim phished into installing an EIP-7702 delegation to an attacker sweeper is
///         drained in one activation (vulnerable); an account that honors only allow-listed
///         delegates rejects the attacker delegate, so the drain is unreachable (protected).
contract Eip7702DelegationTest is Test {
    address constant ATTACKER = address(0xBAD);
    address constant AUDITED = address(0xADD17ED); // a stand-in audited delegate
    uint256 constant BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Vulnerable: the account accepts an arbitrary 7702 delegation (phished) -> the sweeper
    /// runs in the account's context -> one activation drains the whole balance.
    function test_vulnerableTarget_isDrained() public {
        MockERC20 token = new MockERC20();
        VulnerableDelegationAccount account = new VulnerableDelegationAccount();
        token.mint(address(account), BALANCE);

        DelegationSweeper sweeper = new DelegationSweeper();
        // Victim is phished into signing a 7702 authorization to the attacker's sweeper.
        account.installDelegation(address(sweeper));
        // Anyone activates it; delegatecall runs sweep() as the account.
        account.activate(abi.encodeWithSelector(DelegationSweeper.sweep.selector, address(token), ATTACKER));

        bool drained = token.balanceOf(ATTACKER) == BALANCE && token.balanceOf(address(account)) == 0;
        _report("vulnerable-deleg", drained);

        assertTrue(drained, "sweeper should drain the whole account in one tx");
        assertEq(token.balanceOf(ATTACKER), BALANCE, "attacker received the full balance");
    }

    /// Protected: the account honors delegation only to allow-listed delegates; the attacker
    /// sweeper is not allow-listed, so installDelegation reverts -> drain unreachable.
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        SafeDelegationAccount account = new SafeDelegationAccount();
        token.mint(address(account), BALANCE);

        DelegationSweeper sweeper = new DelegationSweeper();
        vm.expectRevert(bytes("delegate not allow-listed"));
        account.installDelegation(address(sweeper));

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("safe-deleg", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(address(account)), BALANCE, "account balance intact");
    }

    /// Guard: an allow-listed (audited) delegate CAN be installed, so BLOCKED is not vacuous.
    function test_protected_auditedDelegateInstalls() public {
        SafeDelegationAccount account = new SafeDelegationAccount();
        account.allow(AUDITED);
        account.installDelegation(AUDITED);
        assertEq(account.delegate(), AUDITED, "allow-listed delegate should install");
    }
}
