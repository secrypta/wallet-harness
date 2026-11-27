// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyErc4337Executor} from
    "../fixtures/malicious-calldata/c-safe-impl/SoladyErc4337Executor.sol";
import {ERC4337Factory} from "../fixtures/vendor/solady-accounts/accounts/ERC4337Factory.sol";

/// @title malicious-calldata tier (c): Solady ERC-4337 gated arbitrary-call executor - holdout.
/// @notice The authorization surface is a canonical ERC-4337 smart account (unmodified Solady
///         ERC4337, deployed via its ERC4337Factory). Its `execute(target,value,data)` is the
///         arbitrary-external-call sink the vector abuses (Socket/LI.FI/Rubic), but it is gated
///         by `onlyEntryPointOrOwner`: an attacker who is neither the EntryPoint nor the owner
///         cannot inject a draining call - it reverts `Unauthorized()`. The harness MUST stay
///         silent here (verdict BLOCKED, label safe). A guard proves the account OWNER can still
///         execute, so BLOCKED is a real rejection, not a dead account. split=holdout.
contract RealSafeErc4337ExecutorHoldoutTest is Test {
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    SoladyErc4337Executor account;
    MockERC20 token;
    address owner;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[malicious-calldata] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _deploy() internal {
        owner = vm.addr(OWNER_PK);
        SoladyErc4337Executor impl = new SoladyErc4337Executor();
        ERC4337Factory factory = new ERC4337Factory(address(impl));
        // The factory encodes the owner in the upper 160 bits of the salt and calls initialize().
        bytes32 salt = bytes32(uint256(uint160(owner)) << 96);
        account = SoladyErc4337Executor(payable(factory.createAccount(salt)));
        token = new MockERC20();
        token.mint(address(account), START_BALANCE);
    }

    /// The attack: an unauthorized caller injects an arbitrary call to drain the account.
    /// The onlyEntryPointOrOwner gate reverts it, so the account keeps its funds.
    function test_maliciousCalldata_erc4337Executor_blocked() public {
        _deploy();

        bytes memory drainCall =
            abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, START_BALANCE);

        // Attacker is neither the EntryPoint nor the owner -> execute reverts Unauthorized().
        vm.prank(ATTACKER);
        vm.expectRevert();
        account.execute(address(token), 0, drainCall);

        bool drained = (token.balanceOf(ATTACKER) > 0 || token.balanceOf(address(account)) < START_BALANCE);
        _report("solady-erc4337-executor-safe", drained);

        assertFalse(drained, "gated ERC-4337 executor must block the injected arbitrary call");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker got nothing");
        assertEq(token.balanceOf(address(account)), START_BALANCE, "account balance intact");
    }

    /// Guard against a vacuous BLOCKED: the account OWNER can still execute an arbitrary call,
    /// so the executor is live - BLOCKED means "the unauthorized injection is stopped", not
    /// "nothing can ever execute".
    function test_maliciousCalldata_erc4337Executor_ownerCanExecute() public {
        _deploy();

        bytes memory benignCall =
            abi.encodeWithSignature("transfer(address,uint256)", owner, 1e18);

        vm.prank(owner);
        account.execute(address(token), 0, benignCall);

        assertEq(token.balanceOf(owner), 1e18, "authorized owner can drive the executor");
        assertEq(token.balanceOf(address(account)), START_BALANCE - 1e18, "only the owner-authorized move happened");
    }
}
