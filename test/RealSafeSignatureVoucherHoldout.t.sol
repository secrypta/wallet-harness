// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SignatureVoucherAirdrop} from
    "../fixtures/fake-airdrop/c-safe-impl/SignatureVoucherAirdrop.sol";

/// @title fake-airdrop tier (c) real-safe HOLDOUT: OpenZeppelin EIP712+ECDSA signature voucher.
/// @notice PRECISION-SIDE safe holdout. No clean independent vuln fake-airdrop incident exists at
///         code level at our provenance bar, so this vector's independent holdouts are genuinely-
///         safe real code the harness MUST stay silent on. Here the claim is gated by an AUTHORITY
///         signature over a typed EIP-712 voucher (unmodified OZ v5.1.0 EIP712 + ECDSA) - distinct
///         from the Merkle-proof holdouts. A forged voucher recovers to a non-authority signer and
///         is rejected; a genuine authority voucher claims exactly its allocation. split=holdout.
contract RealSafeSignatureVoucherHoldoutTest is Test {
    uint256 constant AUTHORITY_PK = 0xA11CE; // the airdrop authority's signing key
    uint256 constant ATTACKER_PK = 0xBAD5EA; // the fake-airdrop operator's key (not the authority)
    address constant ALICE = address(0xA11);
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant POOL = 100e18;
    uint256 constant ALICE_ALLOC = 30e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[fake-airdrop] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _setup() internal returns (MockERC20 token, SignatureVoucherAirdrop air, address authority) {
        authority = vm.addr(AUTHORITY_PK);
        token = new MockERC20();
        air = new SignatureVoucherAirdrop(address(token), authority);
        token.mint(address(air), POOL);
    }

    function test_fakeAirdrop_signatureVoucher_blocked() public {
        (MockERC20 token, SignatureVoucherAirdrop air, ) = _setup();

        // Guard: a genuine authority-signed voucher lets the rightful account claim its allocation
        // (authority is real -> the BLOCKED verdict below is not vacuous).
        bytes32 aliceDigest = air.claimDigest(ALICE, ALICE_ALLOC);
        air.claim(ALICE, ALICE_ALLOC, _sign(AUTHORITY_PK, aliceDigest));
        assertEq(token.balanceOf(ALICE), ALICE_ALLOC, "rightful authority-signed claim should succeed");

        // Attack: the fake-airdrop operator forges a voucher for themselves with their OWN key.
        bytes32 forgedDigest = air.claimDigest(ATTACKER, POOL - ALICE_ALLOC);
        bytes memory forged = _sign(ATTACKER_PK, forgedDigest);
        try air.claim(ATTACKER, POOL - ALICE_ALLOC, forged) {} catch {}

        bool drained = token.balanceOf(ATTACKER) > 0;
        _report("signature-voucher-safe", drained);

        assertFalse(drained, "a forged (non-authority) voucher must not claim");
        assertEq(token.balanceOf(ATTACKER), 0, "fake-airdrop operator gets nothing");
        assertEq(token.balanceOf(address(air)), POOL - ALICE_ALLOC, "only Alice's authorized allocation left");
    }
}
