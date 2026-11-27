// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BlindSigWallet, TypedSigWallet} from "../src/BlindSignVector.sol";

/// @title blind-eth-sign vector (a-toy), proven by test body.
/// @notice A victim who blind-signs an opaque 32-byte hash (legacy eth_sign) hands the attacker
///         a replayable authorization -> drain (vulnerable). A typed-only wallet derives the
///         EIP-712 digest itself from a structured order, so the same blind-signed raw hash does
///         not validate and the drain path is unreachable (protected).
contract BlindEthSignTest is Test {
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

    /// Vulnerable: the owner blind-signs a raw hash the attacker chose; the contract recovers the
    /// signer from that bare hash and executes the hidden transfer.
    function test_vulnerableTarget_isDrained() public {
        address owner = vm.addr(OWNER_PK);
        MockERC20 token = new MockERC20();
        token.mint(owner, BALANCE);

        BlindSigWallet wallet = new BlindSigWallet(owner);
        vm.prank(owner);
        token.approve(address(wallet), type(uint256).max);

        // Attacker crafts the hidden payload and phishes a BLIND signature over its raw hash.
        bytes32 h = keccak256(abi.encode(address(token), ATTACKER, BALANCE));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, h); // raw-hash signing: no prefix, no struct
        wallet.executeBlind(address(token), ATTACKER, BALANCE, v, r, s);

        bool drained = token.balanceOf(ATTACKER) == BALANCE && token.balanceOf(owner) == 0;
        _report("vulnerable-ethsign", drained);

        assertTrue(drained, "blind-signed raw hash should authorize the drain");
        assertEq(token.balanceOf(ATTACKER), BALANCE, "attacker received the full balance");
    }

    /// Protected: the typed-only wallet derives its own EIP-712 digest from the order struct, so
    /// a signature over the attacker's bare hash recovers a signer != owner -> rejected.
    function test_protectedTarget_isBlocked() public {
        address owner = vm.addr(OWNER_PK);
        MockERC20 token = new MockERC20();
        token.mint(owner, BALANCE);

        TypedSigWallet wallet = new TypedSigWallet(owner);
        vm.prank(owner);
        token.approve(address(wallet), type(uint256).max);

        // The attacker only holds a blind raw-hash signature (as in the vulnerable case).
        bytes32 h = keccak256(abi.encode(address(token), ATTACKER, BALANCE));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, h);

        vm.expectRevert(bytes("bad typed signature"));
        wallet.executeTyped(address(token), ATTACKER, BALANCE, 0, v, r, s);

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("safe-ethsign", drained);

        assertFalse(drained, "attacker must receive nothing");
        assertEq(token.balanceOf(owner), BALANCE, "owner balance intact");
    }

    /// Guard: a genuine EIP-712 typed order the owner signed still executes, so BLOCKED above is
    /// "the blind signature was rejected", not "this wallet can never authorize".
    function test_protected_genuineTypedOrderWorks() public {
        address owner = vm.addr(OWNER_PK);
        MockERC20 token = new MockERC20();
        token.mint(owner, BALANCE);

        TypedSigWallet wallet = new TypedSigWallet(owner);
        vm.prank(owner);
        token.approve(address(wallet), type(uint256).max);

        uint256 amount = 10e18;
        bytes32 structHash =
            keccak256(abi.encode(wallet.ORDER_TYPEHASH(), address(token), MERCHANT, amount, uint256(0)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest); // owner signs a DECODABLE order

        wallet.executeTyped(address(token), MERCHANT, amount, 0, v, r, s);
        assertEq(token.balanceOf(MERCHANT), amount, "legit typed order should execute");
    }
}
