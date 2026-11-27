// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Permit2SafeToken} from
    "../fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol";

/// @notice ABI-compatible view of the real Uniswap Permit2 (AllowanceTransfer), declared locally
///         so this test stays in the 0.8.24 / forge-std compile subgraph; the real Permit2 (exact
///         pragma 0.8.17) is compiled separately and deployed by artifact via deployCode. Covers
///         the signature-deadline and PermitBatch surfaces.
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

    struct PermitBatch {
        PermitDetails[] details;
        address spender;
        uint256 sigDeadline;
    }

    function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
    function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
    function allowance(address owner, address token, address spender)
        external
        view
        returns (uint160 amount, uint48 expiration, uint48 nonce);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title permit2-phishing tier (c): real Uniswap Permit2 SIGNATURE-DEADLINE + PermitBatch bounds.
/// @notice All logic exercised is the UNMODIFIED Uniswap Permit2 core (commit cc56ad0, MIT).
///         Two genuine, distinct defenses: (1) a phished permit submitted past its `sigDeadline`
///         is rejected (SignatureExpired) before any allowance is set; (2) a PermitBatch granting
///         bounded per-token amounts cannot be over-drawn. Harness MUST stay silent here (verdict
///         BLOCKED, label safe). split=holdout.
contract RealSafePermit2Round5HoldoutTest is Test {
    uint160 constant START = 100e18;
    uint160 constant ACTION = 10e18;

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );
    bytes32 constant PERMIT_BATCH_TYPEHASH = keccak256(
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    error SignatureExpired(uint256 signatureDeadline);
    error InsufficientAllowance(uint256 amount);
    error AllowanceExpired(uint256 deadline);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit2-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _hashDetails(IPermit2Like.PermitDetails memory d) internal pure returns (bytes32) {
        return keccak256(abi.encode(PERMIT_DETAILS_TYPEHASH, d.token, d.amount, d.expiration, d.nonce));
    }

    function _signSingle(IPermit2Like permit2, uint256 pk, IPermit2Like.PermitSingle memory s)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(PERMIT_SINGLE_TYPEHASH, _hashDetails(s.details), s.spender, s.sigDeadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, digest);
        return abi.encodePacked(r, ss, v);
    }

    function _signBatch(IPermit2Like permit2, uint256 pk, IPermit2Like.PermitBatch memory b)
        internal
        view
        returns (bytes memory)
    {
        bytes32[] memory hashes = new bytes32[](b.details.length);
        for (uint256 i = 0; i < b.details.length; ++i) {
            hashes[i] = _hashDetails(b.details[i]);
        }
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_BATCH_TYPEHASH, keccak256(abi.encodePacked(hashes)), b.spender, b.sigDeadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, digest);
        return abi.encodePacked(r, ss, v);
    }

    /// sigDeadline: a phished permit submitted past its signature deadline is rejected.
    function test_permit2_sigDeadline_realSafe_blocked() public {
        vm.warp(1_000_000);
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START);

        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // Phished UNBOUNDED permit, but with a signature deadline already in the past.
        uint256 expiredSig = block.timestamp - 1;
        IPermit2Like.PermitSingle memory single = IPermit2Like.PermitSingle({
            details: IPermit2Like.PermitDetails({
                token: address(token),
                amount: type(uint160).max,
                expiration: uint48(block.timestamp + 365 days),
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: expiredSig
        });
        bytes memory sig = _signSingle(permit2, ownerPk, single);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, expiredSig));
        permit2.permit(owner, single, sig);

        // No allowance was ever set -> a drain is impossible.
        (uint160 granted,,) = permit2.allowance(owner, address(token), attacker);
        assertEq(granted, 0, "expired-signature permit must grant no allowance");
        // No allowance was ever written, so its expiration is 0: Permit2 checks expiration first
        // and reverts AllowanceExpired(0) before the amount check. Either way the drain reverts.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AllowanceExpired.selector, 0));
        permit2.transferFrom(owner, attacker, START, address(token));

        bool drained = (token.balanceOf(owner) < START);
        _report("permit2-sigdeadline-safe", drained);
        assertFalse(drained, "real Permit2 must reject the past-sigDeadline phishing permit");
        assertEq(token.balanceOf(owner), START, "owner balance intact");
    }

    /// PermitBatch: a bounded multi-token batch cannot be over-drawn.
    function test_permit2_batchScoped_realSafe_blocked() public {
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken tokenA = new Permit2SafeToken();
        Permit2SafeToken tokenB = new Permit2SafeToken();
        uint256 ownerPk = 0xB0B;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        tokenA.mint(owner, START);
        tokenB.mint(owner, START);

        vm.startPrank(owner);
        tokenA.approve(address(permit2), type(uint256).max);
        tokenB.approve(address(permit2), type(uint256).max);
        vm.stopPrank();

        // Canonical safe batch: BOUNDED amount per token.
        IPermit2Like.PermitDetails[] memory details = new IPermit2Like.PermitDetails[](2);
        details[0] = IPermit2Like.PermitDetails({token: address(tokenA), amount: ACTION, expiration: uint48(block.timestamp + 1 hours), nonce: 0});
        details[1] = IPermit2Like.PermitDetails({token: address(tokenB), amount: ACTION, expiration: uint48(block.timestamp + 1 hours), nonce: 0});
        IPermit2Like.PermitBatch memory batch =
            IPermit2Like.PermitBatch({details: details, spender: attacker, sigDeadline: block.timestamp + 1 hours});
        bytes memory sig = _signBatch(permit2, ownerPk, batch);

        vm.prank(attacker);
        permit2.permit(owner, batch, sig);

        // Guard: each bounded spend works (authority is real).
        vm.startPrank(attacker);
        permit2.transferFrom(owner, attacker, ACTION, address(tokenA));
        permit2.transferFrom(owner, attacker, ACTION, address(tokenB));
        vm.stopPrank();
        assertEq(tokenA.balanceOf(attacker), ACTION, "bounded tokenA spend should succeed");
        assertEq(tokenB.balanceOf(attacker), ACTION, "bounded tokenB spend should succeed");

        // Vector: a full-balance pull on tokenA reverts (bounded allowance exhausted).
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(InsufficientAllowance.selector, uint256(ACTION - ACTION)));
        permit2.transferFrom(owner, attacker, START, address(tokenA));

        bool drained = (tokenA.balanceOf(owner) < START - ACTION || tokenB.balanceOf(owner) < START - ACTION);
        _report("permit2-batch-scoped-safe", drained);
        assertFalse(drained, "real Permit2 PermitBatch bounded amounts must not be over-drawn");
        assertEq(tokenA.balanceOf(owner), START - ACTION, "tokenA intact beyond bounded spend");
        assertEq(tokenB.balanceOf(owner), START - ACTION, "tokenB intact beyond bounded spend");
    }
}
