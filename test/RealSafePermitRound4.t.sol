// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OZERC20PermitFixture} from
    "../fixtures/permit-phishing/c-safe-impl/oz-permit-safe/OZERC20PermitFixture.sol";
import {SoladyTokenFixture} from "../fixtures/approve-drainer/c-safe-impl/SoladyERC20Fixture.sol";

/// @title Tier-(c) real-safe fixtures for permit-phishing: DEADLINE + NONCE-REPLAY defenses on
///        real OZ v5.1.0 and real Solady EIP-2612 permit.
/// @notice Three genuinely-distinct defensive properties of real permit code, each proving the
///         harness stays silent (verdict BLOCKED, label safe) on a different phishing sub-attack:
///           - oz-permit-deadline-safe:        a stale/expired permit is rejected (OZ).
///           - oz-permit-nonce-replay-safe:    a captured permit cannot be replayed (OZ).
///           - solady-permit-deadline-safe:    a stale/expired permit is rejected (Solady, holdout).
///         All signature / nonce / deadline logic is the unmodified upstream code.
contract RealSafePermitRound4Test is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what a legit interaction actually needs

    // EIP-2612 type hash (field order per EIP-2612; OZ and Solady both use this order).
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    /// Build an EIP-2612 signature over the given domain separator and nonce.
    function _signPermit(
        bytes32 domainSeparator,
        uint256 nonce,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(OWNER_PK, digest);
    }

    /// permit-phishing, real-safe: OZ permit rejects an EXPIRED-deadline phishing signature.
    function test_permitPhishing_ozDeadline_realSafe_blocked() public {
        vm.warp(1_000_000); // move time forward so an "expired" deadline is well-defined
        OZERC20PermitFixture token = new OZERC20PermitFixture();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        // Phished permit for the FULL balance, but signed with a deadline already in the past.
        uint256 expired = block.timestamp - 1;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            token.DOMAIN_SEPARATOR(), token.nonces(owner), owner, ATTACKER, START_BALANCE, expired
        );

        vm.prank(ATTACKER);
        vm.expectRevert(); // OZ: ERC2612ExpiredSignature(deadline)
        token.permit(owner, ATTACKER, START_BALANCE, expired, v, r, s);

        // No allowance was ever set, so a drain is impossible.
        assertEq(token.allowance(owner, ATTACKER), 0, "expired permit must grant no allowance");
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.transferFrom(owner, ATTACKER, START_BALANCE);

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("oz-permit-deadline-safe", drained);
        assertFalse(drained, "real OZ permit must reject the expired-deadline phishing permit");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact");

        // Guard: a VALID-deadline, BOUNDED permit genuinely works - the revert above is the
        // deadline check, not broken code.
        uint256 good = block.timestamp + 1 hours;
        (v, r, s) = _signPermit(token.DOMAIN_SEPARATOR(), token.nonces(owner), owner, ATTACKER, ACTION_AMOUNT, good);
        vm.prank(ATTACKER);
        token.permit(owner, ATTACKER, ACTION_AMOUNT, good, v, r, s);
        assertEq(token.allowance(owner, ATTACKER), ACTION_AMOUNT, "valid bounded permit still works");
    }

    /// permit-phishing, real-safe: a captured OZ permit signature cannot be REPLAYED.
    function test_permitPhishing_ozNonceReplay_realSafe_blocked() public {
        OZERC20PermitFixture token = new OZERC20PermitFixture();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 deadline = block.timestamp + 1 hours;
        // Owner signs a bounded permit at nonce 0; the attacker captures (v,r,s).
        (uint8 v, bytes32 r, bytes32 s) =
            _signPermit(token.DOMAIN_SEPARATOR(), token.nonces(owner), owner, ATTACKER, ACTION_AMOUNT, deadline);

        // First submission works once (allowance set, nonce consumed 0 -> 1).
        vm.prank(ATTACKER);
        token.permit(owner, ATTACKER, ACTION_AMOUNT, deadline, v, r, s);
        assertEq(token.allowance(owner, ATTACKER), ACTION_AMOUNT, "first use sets bounded allowance");

        // Attacker spends the bounded amount, then REPLAYS the identical signature to try to
        // re-grant allowance. The real OZ nonce check makes the replay recover a wrong signer.
        vm.prank(ATTACKER);
        token.transferFrom(owner, ATTACKER, ACTION_AMOUNT);

        vm.prank(ATTACKER);
        vm.expectRevert(); // OZ: ERC2612InvalidSigner (nonce already consumed -> different digest)
        token.permit(owner, ATTACKER, ACTION_AMOUNT, deadline, v, r, s);

        // The replay granted no new allowance; the remaining balance is not drainable.
        assertEq(token.allowance(owner, ATTACKER), 0, "replay must not re-grant allowance");
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.transferFrom(owner, ATTACKER, START_BALANCE - ACTION_AMOUNT);

        bool drained = (token.balanceOf(owner) < START_BALANCE - ACTION_AMOUNT);
        _report("oz-permit-nonce-replay-safe", drained);
        assertFalse(drained, "real OZ permit must not be re-drainable via a replayed signature");
        assertEq(token.balanceOf(owner), START_BALANCE - ACTION_AMOUNT, "only the one bounded spend left");
    }

    /// permit-phishing, real-safe holdout: Solady permit rejects an EXPIRED-deadline signature.
    function test_permitPhishing_soladyDeadline_realSafe_blocked() public {
        vm.warp(1_000_000);
        SoladyTokenFixture token = new SoladyTokenFixture();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 expired = block.timestamp - 1;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            token.DOMAIN_SEPARATOR(), token.nonces(owner), owner, ATTACKER, START_BALANCE, expired
        );

        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady: PermitExpired()
        token.permit(owner, ATTACKER, START_BALANCE, expired, v, r, s);

        assertEq(token.allowance(owner, ATTACKER), 0, "expired permit must grant no allowance");
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.transferFrom(owner, ATTACKER, START_BALANCE);

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("solady-permit-deadline-safe", drained);
        assertFalse(drained, "real Solady permit must reject the expired-deadline phishing permit");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact");
    }
}
