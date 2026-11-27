// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyERC1271Wallet} from "../fixtures/signature-phishing/c-safe-impl/SoladyERC1271Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT: a forged signature is rejected by UNMODIFIED Solady ERC1271.
/// @notice Solady's ERC1271 (ERC-7739 nested EIP-712) is an independent signature-verification
///         implementation the wal detectors were NEVER tuned against. This is the honest
///         PRECISION test on unseen safe code for the signature-phishing vector: a phishing
///         attempt with a forged signature must NOT authorize a withdrawal, so the harness MUST
///         stay silent (verdict BLOCKED, label safe). A false positive here would be a real,
///         recorded result.
///
///         split=holdout. The signature check that stops the drain is unmodified Solady code.
contract RealSafeSoladyERC1271HoldoutTest is Test {
    uint256 constant FUNDED = 100 ether;
    address constant OWNER = address(0x0E12); // placeholder owner key holder
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory vector, string memory target, bool drained) internal pure {
        console.log(
            string.concat("[", vector, "] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_signaturePhishing_soladyERC1271Safe_blocked() public {
        SoladyERC1271Wallet wallet = new SoladyERC1271Wallet(OWNER);
        vm.deal(address(wallet), FUNDED);

        uint256 balanceBefore = address(wallet).balance;

        // Phishing attempt: a FORGED 65-byte signature (not produced by OWNER's key over the
        // withdrawal digest). Solady's ERC1271 verification rejects it, so the withdrawal does
        // not authorize. The verdict is taken from the real outcome (balance intact), robust to
        // whether the rejection surfaces as our `require` or inside Solady's signature parser.
        bytes memory forged = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27));

        vm.prank(ATTACKER);
        (bool ok,) = address(wallet).call(
            abi.encodeWithSelector(wallet.withdraw.selector, ATTACKER, balanceBefore, forged)
        );

        bool drained = address(wallet).balance < balanceBefore;
        _report("signature-phishing", "solady-erc1271-safe", drained);

        assertFalse(ok, "forged signature must not authorize the withdrawal");
        assertFalse(drained, "real-safe Solady ERC1271 wallet must not pay out on a forged signature");
        assertEq(address(wallet).balance, balanceBefore, "balance must stay intact");
    }
}
