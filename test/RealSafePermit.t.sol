// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OZERC20PermitFixture} from
    "../fixtures/permit-phishing/c-safe-impl/oz-permit-safe/OZERC20PermitFixture.sol";

/// @title Tier-(c) real-safe fixture proof for permit-phishing: bounded permit on REAL OZ.
/// @notice The signature verification, nonce/deadline handling and allowance accounting
///         that cap the spender are the unmodified OZ v5.1.0 ERC20Permit. A bounded permit
///         (value = action amount) is genuinely usable for that amount, but a full-balance
///         drain reverts. The harness MUST stay silent here (verdict BLOCKED, label safe) -
///         the honest 0-false-positives test on real permit code.
contract RealSafePermitTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what the legit interaction actually needs

    // EIP-2612 type hash (field order per OZ: owner, spender, value, nonce, deadline).
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit-phishing] target=", target, " verdict=", verdict));
    }

    function _signBoundedPermit(
        OZERC20PermitFixture token,
        uint256 ownerPk,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, token.nonces(owner), deadline)
        ); // order: owner, spender, value, nonce, deadline (matches PERMIT_TYPEHASH)
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (v, r, s) = vm.sign(ownerPk, digest);
    }

    /// permit-phishing, real-safe: OZ ERC20Permit + bounded permit. Full-balance drain reverts.
    function test_permitPhishing_realSafe_blocked() public {
        OZERC20PermitFixture token = new OZERC20PermitFixture();

        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START_BALANCE);

        // Owner signs a permit for EXACTLY the action amount (bounded), not the balance.
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            _signBoundedPermit(token, ownerPk, owner, attacker, ACTION_AMOUNT, deadline);

        // Anyone can submit the signed permit; model it as the attacker.
        vm.prank(attacker);
        token.permit(owner, attacker, ACTION_AMOUNT, deadline, v, r, s);
        assertEq(token.allowance(owner, attacker), ACTION_AMOUNT, "permit set the bounded allowance");

        // Vector: pulling the full balance must revert (OZ allowance check), assets intact.
        vm.prank(attacker);
        vm.expectRevert(); // OZ ERC20InsufficientAllowance
        token.transferFrom(owner, attacker, START_BALANCE);

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("oz-permit-safe", drained);

        assertFalse(drained, "real-safe OZ permit must not allow a full-balance drain");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact after blocked drain");

        // Guard: the bounded permit is genuinely usable for its amount (authority is real,
        // so BLOCKED is not a false pass).
        vm.prank(attacker);
        token.transferFrom(owner, attacker, ACTION_AMOUNT);
        assertEq(token.balanceOf(attacker), ACTION_AMOUNT, "bounded spend should succeed");
    }
}
