// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {OzSignatureCheckerWallet} from
    "../fixtures/signature-phishing/c-safe-impl/OzSignatureCheckerWallet.sol";

/// @title Tier-(c) real-safe HOLDOUT for signature-phishing: OpenZeppelin `SignatureChecker`.
/// @notice The withdrawal gate is unmodified OZ v5.1.0 `SignatureChecker.isValidSignatureNow`
///         over an OZ `EIP712` typed digest. A forged/phished signature (signed by an attacker
///         key, not the wallet's signer) fails validation, so the withdrawal reverts and the
///         wallet keeps its balance -> the harness must stay silent (BLOCKED, label safe). A
///         guard proves a genuine signer signature DOES withdraw, so BLOCKED is a real
///         rejection, not broken verification. Verdict derived from the real outcome.
contract RealSafeOzSignatureCheckerHoldoutTest is Test {
    uint256 constant SIGNER_PK = 0xA11CE; // the wallet's legitimate signer
    uint256 constant ATTACKER_PK = 0xBAD5EA; // the phisher's key (not authorized)
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _setup() internal returns (MockERC20 token, OzSignatureCheckerWallet wallet, address signer) {
        signer = vm.addr(SIGNER_PK);
        token = new MockERC20();
        wallet = new OzSignatureCheckerWallet(signer);
        token.mint(address(wallet), START_BALANCE);
    }

    /// Protected (c): a forged signature cannot authorize a withdrawal; funds stay put.
    function test_sigPhishing_ozSignatureChecker_blocked() public {
        (MockERC20 token, OzSignatureCheckerWallet wallet,) = _setup();

        bytes32 digest = wallet.withdrawDigest(address(token), ATTACKER, START_BALANCE, 0);
        // Phisher forges a signature with their OWN key over the drain digest.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_PK, digest);
        bytes memory forged = abi.encodePacked(r, s, v);

        vm.prank(ATTACKER);
        try wallet.withdraw(address(token), ATTACKER, START_BALANCE, 0, forged) {} catch {}

        bool drained = (token.balanceOf(address(wallet)) < START_BALANCE);
        _report("oz-sigchecker-safe", drained);

        assertFalse(drained, "forged signature must not authorize a withdrawal");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE, "wallet balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: a genuine signer signature DOES withdraw - so BLOCKED above is a real rejection.
    function test_guard_genuineSignature_withdraws() public {
        (MockERC20 token, OzSignatureCheckerWallet wallet, ) = _setup();
        address to = address(0xC0FFEE);

        bytes32 digest = wallet.withdrawDigest(address(token), to, 10e18, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(ATTACKER); // anyone may relay a validly signed, in-policy withdrawal
        wallet.withdraw(address(token), to, 10e18, 0, sig);

        assertEq(token.balanceOf(to), 10e18, "genuine signed withdrawal should succeed");
        assertEq(token.balanceOf(address(wallet)), START_BALANCE - 10e18, "only the signed amount moved");
    }
}
