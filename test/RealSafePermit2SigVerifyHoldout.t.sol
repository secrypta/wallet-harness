// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {TypedSigGatedVault} from
    "../fixtures/blind-eth-sign/c-safe-impl/TypedSigGatedVault.sol";
import {MockERC20} from "../src/MockERC20.sol";

/// @title blind-eth-sign tier (c) real-safe HOLDOUT: Uniswap Permit2 SignatureVerification.
/// @notice PRECISION-SIDE safe holdout. A withdrawal is authorized ONLY by a signature over a
///         fully-typed EIP-712 digest; a BLIND signature over an opaque raw hash (the eth_sign
///         danger) does not match the typed digest, so the UNMODIFIED Uniswap Permit2
///         SignatureVerification (MIT, commit cc56ad0) recovers signer != owner and reverts.
///         Independent canonical source from signature-phishing's OZ/Solady fixtures, and from
///         this vector's repo-authored dev ClearSigningWallet. See PROVENANCE.md.
contract RealSafePermit2SigVerifyHoldoutTest is Test {
    uint256 constant OWNER_PK = 0xA11CE;
    uint256 constant VAULT_BAL = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_permit2SigVerify_realSafe_blocked() public {
        address owner = vm.addr(OWNER_PK);
        address attacker = address(0xBAD);

        MockERC20 token = new MockERC20();
        TypedSigGatedVault vault = new TypedSigGatedVault(owner, address(token));
        token.mint(address(vault), VAULT_BAL);

        // Guard: a FULLY-TYPED EIP-712 signature by the owner genuinely authorizes a withdrawal
        // (authority is real -> a BLOCKED verdict below is not vacuous).
        uint256 legitAmt = 10e18;
        bytes32 dLegit = vault.digest(owner, legitAmt, vault.nonce());
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(OWNER_PK, dLegit);
        vault.withdraw(owner, legitAmt, abi.encodePacked(r1, s1, v1));
        assertEq(token.balanceOf(owner), legitAmt, "typed signature should authorize withdrawal");

        // Attack: the owner is phished into BLIND-signing an opaque raw hash (eth_sign style) -
        // something a wallet cannot render as a structured action. The attacker replays that
        // signature to try to drain the rest to himself.
        bytes32 blindHash = keccak256("Sign to verify your wallet ownership");
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(OWNER_PK, blindHash);
        bytes memory blindSig = abi.encodePacked(r2, s2, v2);

        // The vault's typed digest for the attacker's intent != blindHash, so the real verifier
        // recovers a signer != owner and reverts (SignatureVerification.InvalidSigner).
        vm.prank(attacker);
        vm.expectRevert();
        vault.withdraw(attacker, VAULT_BAL - legitAmt, blindSig);

        bool drained = token.balanceOf(attacker) > 0;
        _report("permit2-sigverify-safe", drained);

        assertFalse(drained, "a blind (raw-hash) signature must not authorize a withdrawal");
        assertEq(token.balanceOf(attacker), 0, "attacker gets nothing");
        assertEq(
            token.balanceOf(address(vault)),
            VAULT_BAL - legitAmt,
            "only the typed-authorized amount left the vault"
        );
    }
}
