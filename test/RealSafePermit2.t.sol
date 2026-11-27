// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Permit2SafeToken} from
    "../fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol";

/// @notice ABI-compatible view of the real Uniswap Permit2 (AllowanceTransfer). Declared
///         locally so this test stays in the 0.8.24 / forge-std compile subgraph; the real
///         Permit2 (exact pragma 0.8.17) is compiled separately (see Permit2CompileAnchor)
///         and deployed here by artifact via deployCode.
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
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title permit2-phishing tier (c): the REAL vendored Uniswap Permit2 under a scoped policy.
/// @notice The allowance accounting, EIP-712 signature verification, nonce and expiration
///         handling exercised here are the UNMODIFIED Uniswap Permit2 core (commit cc56ad0,
///         MIT) - only its two solmate token-plumbing imports were swapped for an MIT
///         equivalent so the repo stays pure MIT (the safety logic is untouched). A SCOPED
///         Permit2 signature (exact amount, short expiration) is genuinely usable for its
///         amount, but a full-balance transferFrom reverts with the real contract's
///         InsufficientAllowance. The harness MUST stay silent here (verdict BLOCKED, label
///         safe) - the honest 0-false-positive test on genuinely-safe real code.
contract RealSafePermit2Test is Test {
    uint256 constant START_BALANCE = 100e18;
    uint160 constant ACTION_AMOUNT = 10e18;

    // Permit2's own PermitHash typehashes (to produce a valid signature over its struct).
    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    // Mirrors IAllowanceTransfer.InsufficientAllowance(uint256) for expectRevert.
    error InsufficientAllowance(uint256 amount);

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

    function test_permit2_scoped_realSafe_blocked() public {
        // Deploy the REAL vendored Permit2 (compiled at 0.8.17) by artifact.
        IPermit2Like permit2 = IPermit2Like(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();

        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address attacker = address(0xA77ACC);
        token.mint(owner, START_BALANCE);

        // One-time Permit2 approve on the token.
        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // Owner signs a SCOPED PermitSingle: exact action amount, short expiration.
        IPermit2Like.PermitSingle memory single = IPermit2Like.PermitSingle({
            details: IPermit2Like.PermitDetails({
                token: address(token),
                amount: ACTION_AMOUNT,
                expiration: uint48(block.timestamp + 1 hours),
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: block.timestamp + 1 hours
        });
        bytes memory sig = _signSingle(permit2, ownerPk, single);

        vm.startPrank(attacker);
        permit2.permit(owner, single, sig);

        // Vector: pulling the full balance must revert on the REAL Permit2 (bounded allowance).
        vm.expectRevert(abi.encodeWithSelector(InsufficientAllowance.selector, ACTION_AMOUNT));
        permit2.transferFrom(owner, attacker, uint160(START_BALANCE), address(token));
        vm.stopPrank();

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("scoped-permit2-safe", drained);

        assertFalse(drained, "real Permit2 scoped signature must not allow a full drain");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact after blocked drain");

        // Guard: the scoped amount is genuinely pullable (authority is real, BLOCKED not vacuous).
        vm.prank(attacker);
        permit2.transferFrom(owner, attacker, ACTION_AMOUNT, address(token));
        assertEq(token.balanceOf(attacker), ACTION_AMOUNT, "scoped spend should succeed on real Permit2");
    }
}
