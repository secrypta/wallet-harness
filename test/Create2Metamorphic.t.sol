// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {
    BenignLogic,
    DrainerLogic,
    MetamorphicSpender,
    VulnerableApprover,
    CodehashPinnedApprover
} from "../src/Create2Vector.sol";

/// @title create2-metamorphic vector (a-toy), proven by test body.
/// @notice A victim grants a standing approval to a spender carrying benign code; the attacker
///         swaps the code at that same address to a drainer and spends the approval (vulnerable).
///         A codehash-pinning wallet records the spender's code identity at trust time and gates
///         every outflow on it being unchanged, so the swap is rejected (protected). Code
///         mutation at a fixed address is modeled with a swappable implementation (EIP-6780
///         caveat documented in PROVENANCE).
contract Create2MetamorphicTest is Test {
    address constant ATTACKER = address(0xBAD);
    address constant MERCHANT = address(0xC0FFEE);
    uint256 constant BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[create2-metamorphic] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Vulnerable: approve a benign-looking spender, attacker swaps its code to a drainer, the
    /// standing approval now backs hostile logic -> full balance pulled.
    function test_vulnerableTarget_isDrained() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        VulnerableApprover victim = new VulnerableApprover();
        token.mint(address(victim), BALANCE);
        // Victim trusts the (currently benign) spender with a full-balance approval.
        victim.trustAndApprove(address(token), address(spender), type(uint256).max);

        // Metamorphic swap: same address, now a drainer.
        DrainerLogic drainer = new DrainerLogic();
        spender.swapCode(address(drainer));

        // The attacker spends the standing approval via the swapped code (delegatecall keeps the
        // spender as msg.sender to the token).
        spender.execute(
            abi.encodeWithSelector(DrainerLogic.drain.selector, address(token), address(victim), ATTACKER)
        );

        bool drained = token.balanceOf(ATTACKER) == BALANCE && token.balanceOf(address(victim)) == 0;
        _report("vulnerable-create2", drained);

        assertTrue(drained, "swapped drainer should spend the standing approval");
        assertEq(token.balanceOf(ATTACKER), BALANCE, "attacker received the full balance");
    }

    /// Protected: the wallet pins the spender's code identity and re-checks it before any
    /// outflow; after the swap the identity differs, so the guarded settlement reverts.
    function test_protectedTarget_isBlocked() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        CodehashPinnedApprover wallet = new CodehashPinnedApprover();
        token.mint(address(wallet), BALANCE);
        // Trust the spender while it carries benign code: pin its effective code identity.
        wallet.trust(address(spender));

        // Metamorphic swap to a drainer.
        DrainerLogic drainer = new DrainerLogic();
        spender.swapCode(address(drainer));

        // Any attempt to pull through the codehash-gated settlement is rejected.
        vm.expectRevert(bytes("codehash changed - metamorphic swap"));
        wallet.settle(address(token), address(spender), ATTACKER, BALANCE);

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("safe-create2", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(address(wallet)), BALANCE, "funds retained");
    }

    /// Guard: with unchanged code, a legitimate settlement still works, so BLOCKED is not vacuous.
    function test_protected_unchangedCodeSettles() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        CodehashPinnedApprover wallet = new CodehashPinnedApprover();
        token.mint(address(wallet), BALANCE);
        wallet.trust(address(spender));

        // No swap: code identity unchanged -> settlement to a legitimate recipient succeeds.
        wallet.settle(address(token), address(spender), MERCHANT, 10e18);
        assertEq(token.balanceOf(MERCHANT), 10e18, "legit settlement should work");
    }
}
