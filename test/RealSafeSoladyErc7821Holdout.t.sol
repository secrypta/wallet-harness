// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ERC7821} from "../fixtures/vendor/solady-accounts/accounts/ERC7821.sol";
import {SoladyErc7821Wallet} from "../fixtures/eip7702-delegation/c-safe-impl/SoladyErc7821Wallet.sol";

/// @title Tier-(c) real-safe HOLDOUT for eip7702-delegation: Solady `ERC7821` owner-gated.
/// @notice The batch-execution surface an EIP-7702 account exposes is unmodified Solady
///         `ERC7821`; authorization is unmodified Solady `Ownable`. An attacker (a malicious
///         delegate / arbitrary caller that is NOT the owner) submits a batch that would sweep
///         the account's ETH to themselves; `onlyOwner` reverts and nothing leaves ->  the
///         harness must stay silent (BLOCKED, label safe). A guard proves the OWNER can execute
///         a batch, so BLOCKED is a real authorization rejection, not a broken executor.
contract RealSafeSoladyErc7821HoldoutTest is Test {
    address constant OWNER = address(0xBEEF01); // the account's legitimate owner
    address constant ATTACKER = address(0xA77ACC);
    address constant SINK = address(0xC0FFEE); // benign recipient for the guard
    uint256 constant VAULT = 100 ether;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _singleBatchMode() internal pure returns (bytes32) {
        // ERC7821 single-batch mode (no opData): leading byte 0x01, rest zero.
        return bytes32(uint256(1) << 248);
    }

    /// Protected (c): a non-owner batch that would sweep the account reverts; funds stay.
    function test_eip7702_soladyErc7821_blocked() public {
        SoladyErc7821Wallet wallet = new SoladyErc7821Wallet(OWNER);
        vm.deal(address(wallet), VAULT);

        // The malicious delegate's drain batch: send the whole balance to the attacker.
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: ATTACKER, value: VAULT, data: ""});
        bytes memory executionData = abi.encode(calls);

        vm.prank(ATTACKER);
        try wallet.execute(_singleBatchMode(), executionData) {} catch {}

        bool drained = (address(wallet).balance < VAULT);
        _report("solady-erc7821-safe", drained);

        assertFalse(drained, "a non-owner batch must not drain the account");
        assertEq(address(wallet).balance, VAULT, "account balance intact");
        assertEq(ATTACKER.balance, 0, "attacker gets nothing");
    }

    /// Guard: the owner CAN execute a batch - BLOCKED above is a real auth rejection.
    function test_guard_ownerCanExecuteBatch() public {
        SoladyErc7821Wallet wallet = new SoladyErc7821Wallet(OWNER);
        vm.deal(address(wallet), VAULT);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: SINK, value: 1 ether, data: ""});
        bytes memory executionData = abi.encode(calls);

        vm.prank(OWNER);
        wallet.execute(_singleBatchMode(), executionData);

        assertEq(SINK.balance, 1 ether, "owner batch should execute");
        assertEq(address(wallet).balance, VAULT - 1 ether, "only the owner-authorized amount moved");
    }
}
