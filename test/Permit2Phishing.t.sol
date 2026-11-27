// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ToyPermit2} from "../src/ToyPermit2.sol";

/// @title permit2-phishing vector (a-toy), proven by test body.
/// @notice The victim made the one-time `approve(permit2, max)` and now grants pull rights
///         by signing a Permit2 `PermitSingle` off-chain. Signing an UNBOUNDED permit
///         (amount = max, far expiration) to the attacker lets the attacker drain the whole
///         balance via `permit()` + `transferFrom()`. Signing a BOUNDED permit (exact
///         amount, short expiration) caps the damage so a full-balance pull reverts. Same
///         Permit2 flow - only the signed authorization differs.
contract Permit2PhishingTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint160 constant ACTION_AMOUNT = 10e18;

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit2-phishing] target=", target, " verdict=", verdict));
    }

    function _signSingle(
        ToyPermit2 permit2,
        uint256 ownerPk,
        ToyPermit2.PermitSingle memory single
    ) internal view returns (bytes memory sig) {
        bytes32 detailHash = keccak256(
            abi.encode(
                PERMIT_DETAILS_TYPEHASH,
                single.details.token,
                single.details.amount,
                single.details.expiration,
                single.details.nonce
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_SINGLE_TYPEHASH, detailHash, single.spender, single.sigDeadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _setup(uint256 ownerPk)
        internal
        returns (ToyPermit2 permit2, MockERC20 token, address owner)
    {
        permit2 = new ToyPermit2();
        token = new MockERC20();
        owner = vm.addr(ownerPk);
        token.mint(owner, START_BALANCE);
        vm.prank(owner);
        token.approve(address(permit2), type(uint256).max); // the one-time Permit2 approve
    }

    /// Vulnerable target: owner signs an UNBOUNDED PermitSingle -> attacker drains everything.
    function test_vulnerableTarget_isDrained() public {
        uint256 ownerPk = 0xA11CE;
        (ToyPermit2 permit2, MockERC20 token, address owner) = _setup(ownerPk);
        address attacker = address(0xA77ACC);

        ToyPermit2.PermitSingle memory single = ToyPermit2.PermitSingle({
            details: ToyPermit2.PermitDetails({
                token: address(token),
                amount: type(uint160).max, // UNBOUNDED
                expiration: uint48(block.timestamp + 365 days),
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: block.timestamp + 365 days
        });
        bytes memory sig = _signSingle(permit2, ownerPk, single);

        vm.startPrank(attacker);
        permit2.permit(owner, single, sig);
        permit2.transferFrom(owner, attacker, uint160(START_BALANCE), address(token));
        vm.stopPrank();

        bool drained = (token.balanceOf(owner) == 0);
        _report("vulnerable-permit2", drained);

        assertTrue(drained, "unbounded Permit2 signature should drain the balance");
        assertEq(token.balanceOf(attacker), START_BALANCE, "attacker took the full balance");
    }

    /// Protected target: owner signs a BOUNDED PermitSingle -> full-balance pull reverts.
    function test_protectedTarget_isBlocked() public {
        uint256 ownerPk = 0xB0B;
        (ToyPermit2 permit2, MockERC20 token, address owner) = _setup(ownerPk);
        address attacker = address(0xA77ACC);

        ToyPermit2.PermitSingle memory single = ToyPermit2.PermitSingle({
            details: ToyPermit2.PermitDetails({
                token: address(token),
                amount: ACTION_AMOUNT, // BOUNDED to the action need
                expiration: uint48(block.timestamp + 1 hours),
                nonce: 0
            }),
            spender: attacker,
            sigDeadline: block.timestamp + 1 hours
        });
        bytes memory sig = _signSingle(permit2, ownerPk, single);

        vm.startPrank(attacker);
        permit2.permit(owner, single, sig);
        // Vector: a full-balance pull must revert (bounded allowance).
        vm.expectRevert(ToyPermit2.InsufficientAllowance.selector);
        permit2.transferFrom(owner, attacker, uint160(START_BALANCE), address(token));
        vm.stopPrank();

        bool drained = (token.balanceOf(owner) < START_BALANCE);
        _report("safe-permit2", drained);

        assertFalse(drained, "bounded Permit2 signature must not allow a full drain");
        assertEq(token.balanceOf(owner), START_BALANCE, "owner balance intact after blocked drain");

        // Guard: the bounded permit is genuinely usable for its amount (BLOCKED is not vacuous).
        vm.prank(attacker);
        permit2.transferFrom(owner, attacker, ACTION_AMOUNT, address(token));
        assertEq(token.balanceOf(attacker), ACTION_AMOUNT, "bounded spend should succeed");
    }
}
