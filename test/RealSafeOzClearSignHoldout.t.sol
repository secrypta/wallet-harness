// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {OzClearSigningWallet} from "../fixtures/blind-eth-sign/c-safe-impl/OzClearSigningWallet.sol";

/// @title Tier-(c) real-safe HOLDOUT for blind-eth-sign: OZ clear-signing (no raw-hash path).
/// @notice Models the eth_sign blind-signing attack against a clear-signing wallet. The victim
///         is tricked into signing an attacker-chosen OPAQUE 32-byte hash (the eth_sign path -
///         no prefix, no struct). The attacker then tries to replay that signature into a
///         withdrawal. The wallet, built on unmodified OZ v5.1.0 `EIP712` + `ECDSA`, only ever
///         recovers over its OWN typed digest reconstructed from decodable fields; the
///         blind-signed signature recovers to a different address, so authorization fails and
///         nothing leaves the wallet -> the harness must stay silent (BLOCKED, label safe). A
///         guard proves a genuine clear-signed (typed) signature DOES withdraw.
contract RealSafeOzClearSignHoldoutTest is Test {
    uint256 constant SIGNER_PK = 0xA11CE; // the wallet's legitimate signer (the "victim")
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _setup() internal returns (MockERC20 token, OzClearSigningWallet wallet, address signer) {
        signer = vm.addr(SIGNER_PK);
        token = new MockERC20();
        wallet = new OzClearSigningWallet(signer);
        token.mint(address(wallet), START_BALANCE);
    }

    /// Protected (c): a signature produced by blind-signing an opaque hash does not authorize a
    /// withdrawal on the clear-signing wallet.
    function test_blindEthSign_ozClearSign_blocked() public {
        (MockERC20 token, OzClearSigningWallet wallet, ) = _setup();

        // The eth_sign phishing step: the attacker shows the victim an opaque 32-byte hash and
        // the victim blind-signs it (raw hash, no EIP-712 structure, no prefix).
        bytes32 opaqueHash = keccak256(abi.encodePacked("drain:", ATTACKER, START_BALANCE));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, opaqueHash);
        bytes memory blindSig = abi.encodePacked(r, s, v);

        // The attacker replays the blind signature into a withdrawal to themselves.
        vm.prank(ATTACKER);
        try wallet.withdraw(address(token), ATTACKER, START_BALANCE, 0, blindSig) {} catch {}

        bool drained = (token.balanceOf(address(wallet)) < START_BALANCE);
        _report("oz-clearsign-safe", drained);

        assertFalse(drained, "blind-signed opaque hash must not authorize a withdrawal");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "wallet balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: a genuine clear-signed (EIP-712 typed) signature DOES withdraw.
    function test_guard_clearSignedWithdrawal_succeeds() public {
        (MockERC20 token, OzClearSigningWallet wallet, ) = _setup();
        address to = address(0xC0FFEE);

        bytes32 digest = wallet.withdrawDigest(address(token), to, 10e18, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(ATTACKER);
        wallet.withdraw(address(token), to, 10e18, 0, sig);

        assertEq(token.balanceOf(to), 10e18, "clear-signed withdrawal should succeed");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE - 10e18, "only the signed amount moved");
    }
}
