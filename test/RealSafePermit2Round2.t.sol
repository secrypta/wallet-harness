// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Permit2SafeToken} from
    "../fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol";

/// @notice ABI-compatible view of the real Uniswap Permit2 (AllowanceTransfer). Declared
///         locally so this test stays in the 0.8.24 / forge-std compile subgraph; the real
///         Permit2 (exact pragma 0.8.17) is compiled separately (see Permit2CompileAnchor)
///         and deployed here by artifact via deployCode. Covers the revocation surface:
///         `lockdown` and `invalidateNonces`.
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

    struct TokenSpenderPair {
        address token;
        address spender;
    }

    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
    function lockdown(TokenSpenderPair[] calldata approvals) external;
    function invalidateNonces(address token, address spender, uint48 newNonce) external;
    function allowance(address owner, address token, address spender)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title permit2-phishing tier (c): the REAL vendored Uniswap Permit2 REVOCATION surface.
/// @notice The allowance accounting, signature verification, nonce handling, `lockdown` and
///         `invalidateNonces` exercised here are the UNMODIFIED Uniswap Permit2 core (commit
///         cc56ad0, MIT; only its two solmate token-plumbing imports were swapped for an MIT
///         equivalent - the safety logic is untouched). Two genuine Permit2 defenses:
///         (1) `lockdown` zeroes an already-granted (even unbounded) allowance so a later
///             transferFrom reverts; (2) `invalidateNonces` pre-empts a phished signature so
///         it can never be submitted. Harness MUST stay silent here (verdict BLOCKED, label
///         safe) - the honest 0-false-positive test on genuinely-safe real code.
contract RealSafePermit2Round2Test is Test {
    uint256 constant START_BALANCE = 100e18;

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    // Mirror Permit2's own errors for expectRevert.
    error InsufficientAllowance(uint256 amount);
    error InvalidNonce();

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit2-phishing] target=", target, " verdict=", verdict));
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

    function _unboundedSingle(address token, address spender)
        internal
        view
        returns (IPermit2Like.PermitSingle memory)
    {
        return IPermit2Like.PermitSingle({
            details: IPermit2Like.PermitDetails({
                token: token,
                amount: type(uint160).max, // the phished, UNBOUNDED grant
                expiration: uint48(block.timestamp + 365 days),
                nonce: 0
            }),
            spender: spender,
            sigDeadline: block.timestamp + 365 days
        });
    }

    /// lockdown: an already-granted unbounded allowance is zeroed; the full drain then reverts.
    function test_permit2_lockdown_realSafe_blocked() public {
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // The phished, UNBOUNDED permit is actually submitted (allowance really becomes max).
        IPermit2Like.PermitSingle memory single = _unboundedSingle(address(token), attacker);
        bytes memory sig = _signSingle(permit2, ownerPk, single);
        vm.prank(attacker);
        permit2.permit(owner, single, sig);
        (uint160 grantedAmount,,) = permit2.allowance(owner, address(token), attacker);
        assertEq(grantedAmount, type(uint160).max, "unbounded allowance really was granted (grant is real)");

        // Defense: the owner locks down that (token, spender) pair -> allowance zeroed.
        IPermit2Like.TokenSpenderPair[] memory pairs = new IPermit2Like.TokenSpenderPair[](1);
        pairs[0] = IPermit2Like.TokenSpenderPair({token: address(token), spender: attacker});
        vm.prank(owner);
        permit2.lockdown(pairs);

        // Vector: the full-balance pull now reverts on the REAL Permit2 (allowance amount
        // zeroed by lockdown -> InsufficientAllowance(0)).
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(InsufficientAllowance.selector, 0));
        permit2.transferFrom(owner, attacker, uint160(START_BALANCE), address(token));

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("permit2-lockdown-safe", drained);
        assertFalse(drained, "real Permit2 lockdown must stop the drain");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact after lockdown");
    }

    /// invalidateNonces: a phished signature is pre-empted; it can never be submitted.
    function test_permit2_invalidateNonces_realSafe_blocked() public {
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();
        uint256 ownerPk = 0xB0B;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // Owner signs (is phished into) an unbounded permit at nonce 0.
        IPermit2Like.PermitSingle memory single = _unboundedSingle(address(token), attacker);
        bytes memory sig = _signSingle(permit2, ownerPk, single);

        // Defense: the owner invalidates nonce 0 for this (token, spender) before the attacker
        // can submit the captured signature (bumps the stored nonce to 1).
        vm.prank(owner);
        permit2.invalidateNonces(address(token), attacker, 1);

        // Vector: submitting the phished signature now reverts (nonce 0 != stored nonce 1).
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector));
        permit2.permit(owner, single, sig);

        // No allowance was ever set, so a drain is impossible.
        (uint160 grantedAmount,,) = permit2.allowance(owner, address(token), attacker);
        bool drained = (grantedAmount != 0 || token.balanceOf(owner) < START_BALANCE);
        _report("permit2-invalidate-nonce-safe", drained);
        assertFalse(drained, "real Permit2 invalidateNonces must pre-empt the phished signature");
        assertEq(grantedAmount, 0, "no allowance should exist after the phished permit is rejected");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact");
    }
}
