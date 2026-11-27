// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyTypedSigVault} from "../fixtures/blind-eth-sign/c-safe-impl/SoladyTypedSigVault.sol";

/// @title Tier-(c) real-safe HOLDOUT for blind-eth-sign: Solady EIP712 + SignatureCheckerLib.
/// @notice The withdrawal gate is unmodified Solady `SignatureCheckerLib.isValidSignatureNowCalldata`
///         over a Solady `EIP712._hashTypedData` digest, with NO raw-hash / eth_sign entrypoint.
///         The blind-eth-sign danger is a victim tricked into an eth_sign (personal_sign) over an
///         opaque 32-byte blob. Here even the OWNER's signature, if produced over the eth_sign-
///         wrapped hash rather than the bare typed digest, recovers to a different signer and is
///         rejected -> the withdrawal reverts and the vault keeps its balance (BLOCKED, label safe).
///         A guard proves a genuine TYPED signature DOES withdraw, so BLOCKED is a real rejection,
///         not broken verification. split=holdout; verdict derived from the real outcome.
contract RealSafeSoladyTypedSigHoldoutTest is Test {
    uint256 constant OWNER_PK = 0xA11CE; // the vault's legitimate owner
    address constant DEST = address(0xD5E);
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _setup() internal returns (MockERC20 token, SoladyTypedSigVault vault, address owner) {
        owner = vm.addr(OWNER_PK);
        token = new MockERC20();
        vault = new SoladyTypedSigVault(owner, address(token));
        token.mint(address(vault), START_BALANCE);
    }

    /// Protected (c): a BLIND eth_sign signature (personal_sign over the wrapped hash) does not
    /// authorize a typed-digest withdrawal, even when produced by the real owner key.
    function test_blindEthSign_soladyTyped_blocked() public {
        (MockERC20 token, SoladyTypedSigVault vault, ) = _setup();

        bytes32 typedDigest = vault.withdrawDigest(DEST, START_BALANCE, 0);
        // The victim is phished into an eth_sign (personal_sign) over the opaque 32-byte digest:
        // the wallet wraps it with the Ethereum Signed Message prefix before signing.
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedDigest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, ethSigned);
        bytes memory blindSig = abi.encodePacked(r, s, v);

        try vault.withdraw(DEST, START_BALANCE, blindSig) {} catch {}

        bool drained = (token.balanceOf(address(vault)) < START_BALANCE);
        _report("solady-typed-sig-safe", drained);

        assertFalse(drained, "a blind eth_sign signature must not authorize a typed withdrawal");
        assertEq(token.balanceOf(address(vault)), START_BALANCE, "vault balance intact");
        assertEq(token.balanceOf(DEST), 0, "no funds leave on a blind signature");
    }

    /// Guard: a genuine TYPED-digest signature DOES withdraw - so BLOCKED above is a real
    /// rejection of the blind-signed path, not broken verification.
    function test_guard_typedSignature_withdraws() public {
        (MockERC20 token, SoladyTypedSigVault vault, ) = _setup();

        bytes32 typedDigest = vault.withdrawDigest(DEST, 10e18, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, typedDigest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vault.withdraw(DEST, 10e18, sig);

        assertEq(token.balanceOf(DEST), 10e18, "genuine typed-signed withdrawal should succeed");
        assertEq(token.balanceOf(address(vault)), START_BALANCE - 10e18, "only the signed amount moved");
    }
}
