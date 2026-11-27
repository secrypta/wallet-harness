// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Permit2SafeToken} from
    "../fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol";

/// @notice ABI-compatible view of the real Uniswap Permit2 (AllowanceTransfer). Declared
///         locally so this test stays in the 0.8.24 / forge-std compile subgraph; the real
///         Permit2 (exact pragma 0.8.17) is compiled separately and deployed here by artifact
///         via deployCode. Covers the EXPIRATION surface.
interface IPermit2Like {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
    function allowance(address owner, address token, address spender)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title permit2-phishing tier (c): the REAL vendored Uniswap Permit2 EXPIRATION defense.
/// @notice The allowance accounting, signature verification and per-allowance `expiration`
///         enforcement exercised here are the UNMODIFIED Uniswap Permit2 core (commit cc56ad0,
///         MIT). Canonical safe usage: a BOUNDED amount with a short, near-term expiration. Once
///         `block.timestamp` passes that expiration the allowance auto-revokes - `_transfer`
///         reverts `AllowanceExpired` - so a granted allowance cannot be drained later. The
///         harness MUST stay silent here (verdict BLOCKED, label safe); a VULNERABLE would be a
///         real, recorded false positive. split=holdout (independent impl).
contract RealSafePermit2Round4Test is Test {
    uint256 constant START_BALANCE = 100e18;
    uint160 constant ACTION_AMOUNT = 10e18; // exactly what the legit interaction needs

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    // Mirror Permit2's own error for expectRevert.
    error AllowanceExpired(uint256 deadline);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit2-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _signSingle(IPermit2Like permit2, uint256 ownerPk, IPermit2Like.PermitSingle memory s)
        internal
        view
        returns (bytes memory sig)
    {
        bytes32 detailHash = keccak256(
            abi.encode(PERMIT_DETAILS_TYPEHASH, s.details.token, s.details.amount, s.details.expiration, s.details.nonce)
        );
        bytes32 structHash = keccak256(abi.encode(PERMIT_SINGLE_TYPEHASH, detailHash, s.spender, s.sigDeadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s2) = vm.sign(ownerPk, digest);
        sig = abi.encodePacked(r, s2, v);
    }

    /// expiration: a bounded, short-expiry allowance auto-revokes; a later transferFrom reverts.
    function test_permit2_expiration_realSafe_blocked() public {
        vm.warp(1_000_000); // well-defined baseline so expiration arithmetic is unambiguous
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // Canonical safe permit: BOUNDED amount + a short near-term expiration.
        uint48 expiration = uint48(block.timestamp + 1 hours);
        IPermit2Like.PermitSingle memory single = IPermit2Like.PermitSingle({
            details: IPermit2Like.PermitDetails({
                token: address(token),
                amount: ACTION_AMOUNT,
                expiration: expiration,
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: block.timestamp + 1 hours
        });
        bytes memory sig = _signSingle(permit2, ownerPk, single);
        vm.prank(attacker);
        permit2.permit(owner, single, sig);

        // Guard: before expiry the authority is REAL - the spender can pull the bounded amount.
        vm.prank(attacker);
        permit2.transferFrom(owner, attacker, ACTION_AMOUNT, address(token));
        assertEq(token.balanceOf(attacker), ACTION_AMOUNT, "bounded spend should succeed before expiry");

        // Time passes beyond the expiration -> the allowance auto-revokes.
        vm.warp(uint256(expiration) + 1);

        // Vector: any further pull now reverts on the REAL Permit2 (AllowanceExpired).
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AllowanceExpired.selector, uint256(expiration)));
        permit2.transferFrom(owner, attacker, ACTION_AMOUNT, address(token));

        // A full-balance pull is likewise impossible (bounded + expired).
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AllowanceExpired.selector, uint256(expiration)));
        permit2.transferFrom(owner, attacker, uint160(START_BALANCE), address(token));

        uint256 remaining = START_BALANCE - ACTION_AMOUNT;
        bool drained = (token.balanceOf(owner) < remaining);
        _report("permit2-expiration-safe", drained);
        assertFalse(drained, "real Permit2 expiration must stop a post-expiry drain");
        assertEq(token.balanceOf(owner), remaining, "only the one bounded spend left; rest intact");
    }
}
