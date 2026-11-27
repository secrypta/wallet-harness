// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SoladyTokenFixture} from "../fixtures/approve-drainer/c-safe-impl/SoladyERC20Fixture.sol";

/// @title Tier-(c) real-safe HOLDOUT (permit-phishing): NONCE-REPLAY + BOUNDED-VALUE defenses on
///        the independent Solady EIP-2612 permit.
/// @notice The signature / nonce / allowance logic is Solady's unmodified code (never tuned
///         against). split=holdout: the harness MUST stay silent (verdict BLOCKED, label safe).
contract RealSafeSoladyPermitRound5HoldoutTest is Test {
    uint256 constant START = 100e18;
    uint256 constant ACTION = 10e18;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _sign(SoladyTokenFixture token, uint256 nonce, address owner, address spender, uint256 value, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (v, r, s) = vm.sign(OWNER_PK, digest);
    }

    /// permit-phishing, real-safe holdout: a captured Solady permit cannot be REPLAYED.
    function test_permitPhishing_soladyNonceReplay_blocked() public {
        SoladyTokenFixture token = new SoladyTokenFixture();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START);

        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _sign(token, token.nonces(owner), owner, ATTACKER, ACTION, deadline);

        // First submission works once (allowance set, nonce consumed 0 -> 1).
        vm.prank(ATTACKER);
        token.permit(owner, ATTACKER, ACTION, deadline, v, r, s);
        assertEq(token.allowance(owner, ATTACKER), ACTION, "first use sets bounded allowance");

        vm.prank(ATTACKER);
        token.transferFrom(owner, ATTACKER, ACTION);

        // Replay the identical signature -> real Solady reverts (nonce consumed -> wrong signer).
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady: InvalidPermit
        token.permit(owner, ATTACKER, ACTION, deadline, v, r, s);

        assertEq(token.allowance(owner, ATTACKER), 0, "replay must not re-grant allowance");
        vm.prank(ATTACKER);
        vm.expectRevert();
        token.transferFrom(owner, ATTACKER, START - ACTION);

        bool drained = (token.balanceOf(owner) < START - ACTION);
        _report("solady-permit-nonce-replay-safe", drained);
        assertFalse(drained, "real Solady permit must not be re-drainable via a replayed signature");
        assertEq(token.balanceOf(owner), START - ACTION, "only the one bounded spend left");
    }

    /// permit-phishing, real-safe holdout: a BOUNDED Solady permit cannot over-draw.
    function test_permitPhishing_soladyBounded_blocked() public {
        SoladyTokenFixture token = new SoladyTokenFixture();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START);

        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _sign(token, token.nonces(owner), owner, ATTACKER, ACTION, deadline);

        // Owner signs a permit for EXACTLY the action amount (bounded), not the balance.
        vm.prank(ATTACKER);
        token.permit(owner, ATTACKER, ACTION, deadline, v, r, s);
        assertEq(token.allowance(owner, ATTACKER), ACTION, "bounded permit set the bounded allowance");

        // Vector: a full-balance pull must revert (Solady allowance check).
        vm.prank(ATTACKER);
        vm.expectRevert(); // Solady: InsufficientAllowance
        token.transferFrom(owner, ATTACKER, START);

        // Guard: the bounded permit is genuinely usable for its amount (authority is real).
        vm.prank(ATTACKER);
        token.transferFrom(owner, ATTACKER, ACTION);
        assertEq(token.balanceOf(ATTACKER), ACTION, "bounded spend should succeed");

        bool drained = (token.balanceOf(owner) < START - ACTION);
        _report("solady-permit-bounded-safe", drained);
        assertFalse(drained, "real-safe Solady bounded permit must not allow a full-balance drain");
        assertEq(token.balanceOf(owner), START - ACTION, "owner balance intact beyond the bounded spend");
    }
}
