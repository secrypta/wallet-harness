// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ClearSigningWallet} from "../fixtures/blind-eth-sign/c-safe-impl/ClearSigningWallet.sol";

/// @title blind-eth-sign (c) real-safe fixture: clear-signing / typed-only wallet (reference-impl).
/// @notice The 0-false-positive test for the clear-signing defense. The wallet accepts only a
///         decodable EIP-712 typed order whose digest it derives itself, so a signature obtained
///         by blind-signing a bare hash cannot authorize anything (recovered signer != owner) ->
///         the blind-hash drain path is unreachable (BLOCKED). A guard executes a genuine typed
///         order the owner signed, so BLOCKED means "blind signature rejected", not "nothing
///         works".
contract RealSafeBlindSignTest is Test {
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xBAD);
    address constant MERCHANT = address(0xBEEF);
    uint256 constant BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Safe: a blind raw-hash signature does not validate against the typed-only wallet.
    function test_clearSigning_blocksBlindSignature() public {
        address owner = vm.addr(OWNER_PK);
        MockERC20 token = new MockERC20();
        token.mint(owner, BALANCE);

        ClearSigningWallet wallet = new ClearSigningWallet(owner);
        vm.prank(owner);
        token.approve(address(wallet), type(uint256).max);

        // Attacker holds only a blind signature over a bare hash.
        bytes32 h = keccak256(abi.encode(address(token), ATTACKER, BALANCE));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, h);

        vm.expectRevert(ClearSigningWallet.BlindOrUnauthorizedSignature.selector);
        wallet.executeOrder(address(token), ATTACKER, BALANCE, 0, v, r, s);

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("typed-only-safe", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(owner), BALANCE, "owner balance intact");
    }

    /// Guard: a genuine EIP-712 typed order the owner signed executes normally.
    function test_guard_genuineTypedOrderWorks() public {
        address owner = vm.addr(OWNER_PK);
        MockERC20 token = new MockERC20();
        token.mint(owner, BALANCE);

        ClearSigningWallet wallet = new ClearSigningWallet(owner);
        vm.prank(owner);
        token.approve(address(wallet), type(uint256).max);

        uint256 amount = 15e18;
        bytes32 structHash =
            keccak256(abi.encode(wallet.ORDER_TYPEHASH(), address(token), MERCHANT, amount, uint256(0)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        wallet.executeOrder(address(token), MERCHANT, amount, 0, v, r, s);
        assertEq(token.balanceOf(MERCHANT), amount, "legit typed order should execute");
    }
}
