// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {TimelockController} from "../fixtures/vendor/oz/governance/TimelockController.sol";
import {LibClone} from "../fixtures/vendor/solady-accounts/utils/LibClone.sol";
import {
    SoladyTimelockUUPSWallet,
    SoladyTimelockUUPSWalletV2,
    SoladyDrainUpgradeImpl
} from "../fixtures/upgrade-governance/c-safe-impl/solady-uups-timelock-safe/SoladyTimelockUUPSWallet.sol";

/// @title upgrade-governance tier (c) - genuinely-safe REAL code (Solady UUPS, holdout).
/// @notice Independent of the OZ `oz-timelock-safe` fixture: the upgrade machinery is Solady
///         `UUPSUpgradeable` and the authority is a real OZ `TimelockController`. A single
///         compromised key cannot instant-swap the implementation (the direct upgrade reverts
///         in `_authorizeUpgrade`), and a legitimate timelock-scheduled upgrade still applies
///         after the delay (so BLOCKED is not vacuous). The harness must stay silent.
contract RealSafeUpgradeGovernanceSoladyTest is Test {
    address constant PROPOSER = address(0x9401);
    address constant EXECUTOR = address(0x9402);
    address constant ATTACKER = address(0xBAD66);

    uint256 constant MIN_DELAY = 2 days;
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    function _deploy()
        internal
        returns (MockERC20 token, TimelockController timelock, SoladyTimelockUUPSWallet wallet)
    {
        token = new MockERC20();

        address[] memory proposers = new address[](1);
        proposers[0] = PROPOSER;
        address[] memory executors = new address[](1);
        executors[0] = EXECUTOR;
        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(0));

        SoladyTimelockUUPSWallet impl = new SoladyTimelockUUPSWallet();
        // Solady's canonical ERC-1967 proxy for its UUPS implementation.
        address proxy = LibClone.deployERC1967(address(impl));
        SoladyTimelockUUPSWallet(proxy).initialize(address(timelock));
        wallet = SoladyTimelockUUPSWallet(proxy);
        token.mint(address(wallet), START_BALANCE);
    }

    function test_realSafe_instantUpgradeBlocked() public {
        (MockERC20 token, TimelockController timelock, SoladyTimelockUUPSWallet wallet) = _deploy();
        SoladyDrainUpgradeImpl evil = new SoladyDrainUpgradeImpl();

        // Compromised single key tries to swap in the draining implementation right now.
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("upgrade: not authorized"));
        wallet.upgradeToAndCall(address(evil), abi.encodeWithSignature("sweep(address,address)", address(token), ATTACKER));

        bool drained = (token.balanceOf(ATTACKER) > 0);
        _report("solady-uups-timelock-safe", drained);

        assertFalse(drained, "timelock-gated Solady UUPS upgrade must prevent the instant drain");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker got nothing");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "wallet balance intact");
        assertEq(wallet.version(), 1, "implementation unchanged");
        assertEq(wallet.upgradeAuthority(), address(timelock), "authority is the timelock");
    }

    function test_realSafe_legitTimelockUpgradeApplies() public {
        (, TimelockController timelock, SoladyTimelockUUPSWallet wallet) = _deploy();
        SoladyTimelockUUPSWalletV2 implV2 = new SoladyTimelockUUPSWalletV2();

        bytes memory upgradeCall =
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(implV2), "");

        vm.prank(PROPOSER);
        timelock.schedule(address(wallet), 0, upgradeCall, bytes32(0), bytes32(0), MIN_DELAY);

        vm.prank(EXECUTOR);
        vm.expectRevert(); // operation not ready before the delay elapses
        timelock.execute(address(wallet), 0, upgradeCall, bytes32(0), bytes32(0));

        vm.warp(block.timestamp + MIN_DELAY + 1);
        vm.prank(EXECUTOR);
        timelock.execute(address(wallet), 0, upgradeCall, bytes32(0), bytes32(0));

        assertEq(wallet.version(), 2, "legit timelock-governed upgrade must apply after delay");
    }
}
