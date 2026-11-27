// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Permit2SafeToken} from
    "../fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/Permit2SafeToken.sol";

/// @notice ABI-compatible view of the real Uniswap Permit2 SignatureTransfer surface. Declared
///         locally so this test stays in the 0.8.24 / forge-std compile subgraph; the real
///         Permit2 (exact pragma 0.8.17) is compiled separately (Permit2CompileAnchor) and
///         deployed here by artifact via deployCode.
interface IPermit2SigTransfer {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    function permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;

    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @title permit2-phishing tier (c) real-safe HOLDOUT: real Permit2 SignatureTransfer.
/// @notice PRECISION-SIDE safe holdout. Exercises the UNMODIFIED Uniswap Permit2 (commit
///         cc56ad0, MIT) via its SignatureTransfer path (permitTransferFrom) - a DISTINCT
///         surface from the dev scoped-permit2-safe fixture (AllowanceTransfer). A one-time,
///         amount-bounded, deadline-scoped signature transfers only the signed amount and
///         cannot be over-drawn or replayed. The harness MUST stay silent (BLOCKED). The
///         signature-verification / nonce / amount logic is unmodified Permit2. See PROVENANCE.md.
contract RealSafePermit2SigTransferHoldoutTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18;

    // Permit2's own PermitHash typehashes (to produce a valid signature over its struct).
    bytes32 constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    // Mirrors ISignatureTransfer.InvalidAmount(uint256) for expectRevert.
    error InvalidAmount(uint256 maxAmount);

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[permit2-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// @dev Signs a PermitTransferFrom for `spender` (= the msg.sender that will call permit2).
    function _sign(
        IPermit2SigTransfer permit2,
        uint256 ownerPk,
        address spender,
        IPermit2SigTransfer.PermitTransferFrom memory p
    ) internal view returns (bytes memory) {
        bytes32 tph =
            keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, p.permitted.token, p.permitted.amount));
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TRANSFER_FROM_TYPEHASH, tph, spender, p.nonce, p.deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_permit2_sigTransfer_realSafe_blocked() public {
        // Deploy the REAL vendored Permit2 (compiled at 0.8.17) by artifact.
        IPermit2SigTransfer permit2 = IPermit2SigTransfer(deployCode("Permit2.sol:Permit2"));
        Permit2SafeToken token = new Permit2SafeToken();

        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        address spender = address(0xA77ACC); // the party authorized by the signature (= msg.sender)
        token.mint(owner, START_BALANCE);

        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max);

        // Owner signs a SCOPED one-shot permit: exact bounded amount, near deadline, nonce 0.
        IPermit2SigTransfer.PermitTransferFrom memory p = IPermit2SigTransfer.PermitTransferFrom({
            permitted: IPermit2SigTransfer.TokenPermissions({token: address(token), amount: ACTION_AMOUNT}),
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        bytes memory sig = _sign(permit2, ownerPk, spender, p);

        vm.startPrank(spender);

        // Vector: pull the FULL balance (requested > signed) must revert on the REAL Permit2.
        vm.expectRevert(abi.encodeWithSelector(InvalidAmount.selector, ACTION_AMOUNT));
        permit2.permitTransferFrom(
            p,
            IPermit2SigTransfer.SignatureTransferDetails({to: spender, requestedAmount: START_BALANCE}),
            owner,
            sig
        );

        // Guard: the bounded signed amount IS genuinely pullable (authority real -> not vacuous).
        permit2.permitTransferFrom(
            p,
            IPermit2SigTransfer.SignatureTransferDetails({to: spender, requestedAmount: ACTION_AMOUNT}),
            owner,
            sig
        );
        assertEq(token.balanceOf(spender), ACTION_AMOUNT, "bounded signed amount should transfer");

        // Vector: replay the same signature (nonce consumed) must revert (InvalidNonce).
        vm.expectRevert();
        permit2.permitTransferFrom(
            p,
            IPermit2SigTransfer.SignatureTransferDetails({to: spender, requestedAmount: ACTION_AMOUNT}),
            owner,
            sig
        );
        vm.stopPrank();

        bool drained = token.balanceOf(owner) < START_BALANCE - ACTION_AMOUNT;
        _report("permit2-sigtransfer-safe", drained);

        assertFalse(drained, "real Permit2 SignatureTransfer must not allow over-draw or replay");
        assertEq(token.balanceOf(owner), START_BALANCE - ACTION_AMOUNT, "only one bounded transfer left the owner");
        assertEq(token.balanceOf(spender), ACTION_AMOUNT, "spender received exactly the signed amount");
    }
}
