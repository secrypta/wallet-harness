// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {OZMulticallRouter} from
    "../fixtures/malicious-calldata/c-safe-impl/oz-multicall-safe/OZMulticallRouter.sol";
import {SoladyMulticallableRouter} from
    "../fixtures/malicious-calldata/c-safe-impl/solady-multicallable-safe/SoladyMulticallableRouter.sol";
import {TimelockController} from "../fixtures/vendor/oz/governance/TimelockController.sol";
import {SoladyRolesExecutor} from
    "../fixtures/malicious-calldata/c-safe-impl/solady-ownableroles-executor-safe/SoladyRolesExecutor.sol";

/// @dev A benign target the timelock legitimately calls (proves the gated executor works).
contract BenignSink {
    uint256 public pinged;

    function ping() external {
        pinged += 1;
    }
}

/// @title malicious-calldata tier (c): real self-only multicall must NOT enable arbitrary-call
///        injection (OpenZeppelin Multicall + Solady Multicallable, holdout precision).
/// @notice Both real libraries batch calls by delegatecall to `address(this)` only, so a
///         caller cannot supply an external target+calldata to drain a standing approval (the
///         Socket vector). Each test holds a victim's approval to the router, injects a
///         `transferFrom(victim, attacker, ...)` via `multicall`, and confirms the approval is
///         untouched (the injected call cannot reach the external token). A legitimate self-op
///         (`poke`) still works, so BLOCKED is not vacuous. The harness must stay silent.
contract RealSafeMaliciousCalldataTest is Test {
    uint256 constant VICTIM_BALANCE = 250_000e18;
    address constant VICTIM = address(0x5017);
    address constant ATTACKER = address(0xBAD44);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_ozMulticall_selfOnly_blocksArbitraryCallInjection() public {
        MockERC20 token = new MockERC20();
        OZMulticallRouter router = new OZMulticallRouter();

        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(router), type(uint256).max); // standing approval, as Socket users had

        // Legit self-op proves the batch path works (non-vacuous).
        bytes[] memory legit = new bytes[](1);
        legit[0] = abi.encodeWithSelector(OZMulticallRouter.poke.selector);
        router.multicall(legit);
        assertEq(router.pokes(), 1, "legit multicall self-op must work");

        // Injection attempt: encode a transferFrom and try to run it through multicall. OZ
        // Multicall self-delegatecalls the router, which has no such function / no external-call
        // sink, so the injected drain cannot reach the token. (The call may revert; either way
        // no approval is spent.)
        bytes[] memory injected = new bytes[](1);
        injected[0] =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        (bool ok,) = address(router).call(abi.encodeWithSignature("multicall(bytes[])", injected));
        ok; // outcome irrelevant - the invariant is that the victim is not drained

        bool drained = (token.balanceOf(ATTACKER) != 0 || token.balanceOf(VICTIM) != VICTIM_BALANCE);
        _report("oz-multicall-safe", drained);
        assertFalse(drained, "self-only multicall must not let injected calldata drain the approval");
        assertEq(token.balanceOf(VICTIM), VICTIM_BALANCE, "victim balance intact");
    }

    function test_soladyMulticallable_selfOnly_blocksArbitraryCallInjection() public {
        MockERC20 token = new MockERC20();
        SoladyMulticallableRouter router = new SoladyMulticallableRouter();

        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(router), type(uint256).max);

        bytes[] memory legit = new bytes[](1);
        legit[0] = abi.encodeWithSelector(SoladyMulticallableRouter.poke.selector);
        router.multicall(legit);
        assertEq(router.pokes(), 1, "legit multicall self-op must work");

        bytes[] memory injected = new bytes[](1);
        injected[0] =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        (bool ok,) =
            address(router).call(abi.encodeWithSignature("multicall(bytes[])", injected));
        ok;

        bool drained = (token.balanceOf(ATTACKER) != 0 || token.balanceOf(VICTIM) != VICTIM_BALANCE);
        _report("solady-multicallable-safe", drained);
        assertFalse(drained, "self-only multicall must not let injected calldata drain the approval");
        assertEq(token.balanceOf(VICTIM), VICTIM_BALANCE, "victim balance intact");
    }

    /// @notice OpenZeppelin TimelockController as a GATED arbitrary-call executor. Its
    ///         `execute(target, value, payload, ...)` is a genuine arbitrary-external-call sink,
    ///         but reaching it needs EXECUTOR_ROLE + a prior `schedule` (PROPOSER_ROLE) + an
    ///         elapsed min-delay. An attacker holding neither role cannot inject a
    ///         `transferFrom` against the victim's standing approval. A legit proposer/executor
    ///         pair runs a benign call after the delay (non-vacuous).
    function test_ozTimelockExecutor_gated_blocksArbitraryCallInjection() public {
        MockERC20 token = new MockERC20();
        address proposer = address(0x9401);
        address executor = address(0x9402);
        uint256 minDelay = 2 days;

        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = executor;
        TimelockController timelock = new TimelockController(minDelay, proposers, executors, address(0));

        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(timelock), type(uint256).max); // standing approval to the executor

        bytes memory drainCall =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);

        // Injection attempt (a): execute an unscheduled drain - attacker lacks EXECUTOR_ROLE and
        // the op was never scheduled, so it reverts.
        vm.prank(ATTACKER);
        (bool okExec,) = address(timelock).call(
            abi.encodeWithSignature(
                "execute(address,uint256,bytes,bytes32,bytes32)",
                address(token), uint256(0), drainCall, bytes32(0), bytes32(0)
            )
        );
        assertFalse(okExec, "unscheduled execute by a non-executor must fail");

        // Injection attempt (b): schedule the drain - attacker lacks PROPOSER_ROLE, so it reverts.
        vm.prank(ATTACKER);
        (bool okSched,) = address(timelock).call(
            abi.encodeWithSignature(
                "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
                address(token), uint256(0), drainCall, bytes32(0), bytes32(0), minDelay
            )
        );
        assertFalse(okSched, "schedule by a non-proposer must fail");

        // Non-vacuous: a proposer schedules a benign call; the executor runs it after the delay.
        BenignSink sink = new BenignSink();
        bytes memory benignCall = abi.encodeWithSignature("ping()");
        vm.prank(proposer);
        timelock.schedule(address(sink), 0, benignCall, bytes32(0), bytes32(0), minDelay);
        vm.warp(block.timestamp + minDelay + 1);
        vm.prank(executor);
        timelock.execute(address(sink), 0, benignCall, bytes32(0), bytes32(0));
        assertEq(sink.pinged(), 1, "legit gated execution works (non-vacuous)");

        bool drained = (token.balanceOf(ATTACKER) != 0 || token.balanceOf(VICTIM) != VICTIM_BALANCE);
        _report("oz-timelock-executor-safe", drained);
        assertFalse(drained, "gated executor blocks arbitrary-call injection against the approval");
        assertEq(token.balanceOf(VICTIM), VICTIM_BALANCE, "victim balance intact");
    }

    /// @notice Solady OwnableRoles-gated arbitrary-call executor. `execute(target,data)` is a
    ///         genuine external-call sink, but gated by `onlyOwnerOrRoles` - an unauthorized
    ///         attacker cannot inject a `transferFrom` against the victim's standing approval.
    ///         A different gate (owner/role, no delay) than the self-only multicalls and the
    ///         role+delay timelock above.
    function test_soladyRolesExecutor_gated_blocksArbitraryCallInjection() public {
        address execOwner = address(0x0E7E);
        MockERC20 token = new MockERC20();
        SoladyRolesExecutor exec = new SoladyRolesExecutor(execOwner);

        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(exec), type(uint256).max); // standing approval to the executor

        // Injection attempt: unauthorized attacker tries to drain via the execute sink -> reverts
        // (not owner, no EXECUTOR_ROLE), so no approval is spent.
        vm.prank(ATTACKER);
        (bool okInject,) = address(exec).call(
            abi.encodeWithSignature(
                "execute(address,uint256,bytes)",
                address(token),
                uint256(0),
                abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE)
            )
        );
        assertFalse(okInject, "unauthorized execute must revert");

        // Non-vacuous: the owner legitimately executes a benign call through the sink.
        BenignSink sink = new BenignSink();
        vm.prank(execOwner);
        exec.execute(address(sink), 0, abi.encodeWithSignature("ping()"));
        assertEq(sink.pinged(), 1, "authorized owner can use the execute sink (non-vacuous)");

        bool drained = (token.balanceOf(ATTACKER) != 0 || token.balanceOf(VICTIM) != VICTIM_BALANCE);
        _report("solady-ownableroles-executor-safe", drained);
        assertFalse(drained, "owner/role-gated executor blocks arbitrary-call injection");
        assertEq(token.balanceOf(VICTIM), VICTIM_BALANCE, "victim balance intact");
    }
}
