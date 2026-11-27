// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {SoladyErc4337Fixture} from
    "../fixtures/signature-phishing/c-safe-impl/SoladyErc4337Fixture.sol";
import {ERC4337Factory} from "../fixtures/vendor/solady-accounts/accounts/ERC4337Factory.sol";

/// @title Tier-(c) real-safe HOLDOUT for signature-phishing: ERC-4337 userOp signature validation.
/// @notice The authorization surface is a canonical ERC-4337 smart account (unmodified Solady
///         ERC4337, deployed via its ERC4337Factory). A UserOperation is only executed by the
///         EntryPoint if `validateUserOp` returns success (0). A userOp whose signature was forged
///         by an attacker (not the account owner) returns 1 (SIG_VALIDATION_FAILED), so the
///         EntryPoint never runs its calldata and the account keeps its funds -> the harness MUST
///         stay silent (verdict BLOCKED, label safe). A guard proves a genuine owner-signed userOp
///         validates (0) and its executed call moves funds, so BLOCKED is a real rejection, not a
///         dead account. split=holdout; verdict derived from the real outcome.
contract RealSafeErc4337UserOpHoldoutTest is Test {
    uint256 constant OWNER_PK = 0xA11CE;
    uint256 constant ATTACKER_PK = 0xBAD5EA;
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant START_BALANCE = 100e18;

    SoladyErc4337Fixture account;
    MockERC20 token;
    address entryPoint;
    address owner;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _deploy() internal {
        owner = vm.addr(OWNER_PK);
        SoladyErc4337Fixture impl = new SoladyErc4337Fixture();
        ERC4337Factory factory = new ERC4337Factory(address(impl));
        // The factory encodes the owner in the upper 160 bits of the salt and calls initialize().
        bytes32 salt = bytes32(uint256(uint160(owner)) << 96);
        account = SoladyErc4337Fixture(payable(factory.createAccount(salt)));
        token = new MockERC20();
        token.mint(address(account), START_BALANCE);
        entryPoint = account.entryPoint();
    }

    function _userOp(bytes memory callData, bytes memory signature)
        internal
        view
        returns (SoladyErc4337Fixture.PackedUserOperation memory op)
    {
        op.sender = address(account);
        op.nonce = 0;
        op.callData = callData;
        op.signature = signature;
        // other fields default to zero / empty - only the signature is checked here.
    }

    function _sign(uint256 pk, bytes32 userOpHash) internal pure returns (bytes memory) {
        // ERC4337._validateSignature checks against toEthSignedMessageHash(userOpHash).
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSigned);
        return abi.encodePacked(r, s, v);
    }

    function test_sigPhishing_erc4337UserOp_blocked() public {
        _deploy();

        bytes memory drainCall =
            abi.encodeWithSignature("execute(address,uint256,bytes)", address(token), uint256(0),
                abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, START_BALANCE));

        // userOpHash the (honest) EntryPoint would present; the phisher forges its signature.
        bytes32 userOpHash = keccak256("drain-user-op");
        bytes memory forgedSig = _sign(ATTACKER_PK, userOpHash);

        SoladyErc4337Fixture.PackedUserOperation memory op = _userOp(drainCall, forgedSig);

        // The EntryPoint calls validateUserOp; it executes the calldata only if validation == 0.
        vm.prank(entryPoint);
        uint256 validationData = account.validateUserOp(op, userOpHash, 0);

        if (validationData == 0) {
            // (would only happen on a genuine signature) the EntryPoint would now run the calldata
            vm.prank(entryPoint);
            account.execute(address(token), 0,
                abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, START_BALANCE));
        }

        bool drained = (token.balanceOf(address(account)) < START_BALANCE) || token.balanceOf(ATTACKER) > 0;
        _report("solady-erc4337-userop-safe", drained);

        assertEq(validationData, 1, "a forged userOp signature must fail validation (SIG_VALIDATION_FAILED)");
        assertFalse(drained, "a forged userOp must not drain the account");
        assertEq(token.balanceOf(address(account)), START_BALANCE, "account balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
    }

    /// Guard: a genuine owner-signed userOp validates (0) and its executed call moves funds - so
    /// BLOCKED above is a real rejection of the forged signature, not a dead account.
    function test_guard_ownerUserOp_executes() public {
        _deploy();
        address dest = address(0xC0FFEE);

        bytes32 userOpHash = keccak256("honest-user-op");
        bytes memory sig = _sign(OWNER_PK, userOpHash);
        SoladyErc4337Fixture.PackedUserOperation memory op = _userOp("", sig);

        vm.prank(entryPoint);
        uint256 validationData = account.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "genuine owner userOp signature should validate");

        vm.prank(entryPoint);
        account.execute(address(token), 0,
            abi.encodeWithSignature("transfer(address,uint256)", dest, 10e18));

        assertEq(token.balanceOf(dest), 10e18, "owner-authorized execute should move funds");
        assertEq(token.balanceOf(address(account)), START_BALANCE - 10e18, "only the owner-moved amount left");
    }
}
