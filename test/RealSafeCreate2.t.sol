// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BenignLogic, DrainerLogic, MetamorphicSpender} from "../src/Create2Vector.sol";
import {CodehashPinnedVault} from "../fixtures/create2-metamorphic/c-safe-impl/CodehashPinnedVault.sol";

/// @title create2-metamorphic (c) real-safe fixture: codehash-pinning vault (reference-impl).
/// @notice The 0-false-positive test for the canonical codehash-pinning defense. The vault pins
///         the approved spender's effective code identity at trust time and re-verifies it on
///         every outflow; after the metamorphic swap the identity differs, so the drain path
///         reverts and nothing leaves (BLOCKED). A guard settles with unchanged code, so BLOCKED
///         means "the swapped code was rejected", not "this vault can never pay".
contract RealSafeCreate2Test is Test {
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

    /// Safe: the metamorphic swap changes the spender's code identity -> guarded settle reverts.
    function test_codehashPinned_blocksMetamorphicSwap() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        CodehashPinnedVault vault = new CodehashPinnedVault();
        token.mint(address(vault), BALANCE);
        vault.trust(address(spender));

        DrainerLogic drainer = new DrainerLogic();
        spender.swapCode(address(drainer));

        vm.expectRevert(
            abi.encodeWithSelector(
                CodehashPinnedVault.CodeIdChanged.selector,
                address(spender),
                address(benign).codehash,
                address(drainer).codehash
            )
        );
        vault.settle(address(token), address(spender), ATTACKER, BALANCE);

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("codehash-pinned-safe", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(address(vault)), BALANCE, "funds retained");
    }

    /// Guard: with unchanged code, a legitimate settlement still works.
    function test_guard_unchangedCodeSettles() public {
        MockERC20 token = new MockERC20();
        BenignLogic benign = new BenignLogic();
        MetamorphicSpender spender = new MetamorphicSpender(address(benign));

        CodehashPinnedVault vault = new CodehashPinnedVault();
        token.mint(address(vault), BALANCE);
        vault.trust(address(spender));

        vault.settle(address(token), address(spender), MERCHANT, 25e18);
        assertEq(token.balanceOf(MERCHANT), 25e18, "legit settlement should work");
    }
}
