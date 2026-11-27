// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {MaliciousSpender} from "../src/MaliciousSpender.sol";

/// @title Permit-phishing vector (EIP-2612), proven by test body.
/// @notice Flow is identical for both targets: the owner signs an off-chain permit, an
///         attacker submits it to set the allowance, then tries to pull the FULL balance.
///         The only difference is the VALUE the owner was lured into signing. The probe
///         measures the real on-chain outcome and derives the verdict; the harness
///         (harness/run.sh) reads the "[permit-phishing] target=... verdict=..." lines.
///         Guard tests assert the signature checks hold, so "BLOCKED" is never a false
///         pass caused by a malformed signature.
contract PermitPhishingTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what the legit interaction actually needs
    uint256 constant OWNER_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);

    /// @dev EIP-712 digest matching MockERC20.permit, for the owner's current nonce.
    function _digest(MockERC20 token, address owner, address spender, uint256 value, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(token.PERMIT_TYPEHASH(), owner, spender, value, token.nonces(owner), deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    }

    /// @dev Runs the full permit-phishing flow for one signing policy and returns whether
    ///      the malicious spender managed to empty the owner.
    function _runVector(bool safePolicy) internal returns (bool drained, uint256 finalBalance) {
        MockERC20 token = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        // Unsafe policy: owner is lured into signing an UNLIMITED-value permit.
        // Safe policy: owner signs a permit for exactly the action amount.
        uint256 signedValue = safePolicy ? ACTION_AMOUNT : type(uint256).max;
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(OWNER_PK, _digest(token, owner, address(spender), signedValue, deadline));

        // The owner never sends a tx; the attacker submits the signature, then drains.
        vm.prank(ATTACKER);
        token.permit(owner, address(spender), signedValue, deadline, v, r, s);

        uint256 balanceBefore = token.balanceOf(owner);
        vm.prank(ATTACKER);
        try spender.drain(address(token), owner) {
            // drain succeeded
        } catch {
            // drain reverted (signed value too small): nothing taken
        }

        finalBalance = token.balanceOf(owner);
        drained = (balanceBefore > 0 && finalBalance == 0);
    }

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    /// Vulnerable target: unlimited-value permit lets the spender take 100%.
    function test_vulnerableTarget_isDrained() public {
        (bool drained, uint256 finalBalance) = _runVector(false);
        _report("vulnerable-permit", drained);

        assertTrue(drained, "vulnerable target was not drained");
        assertEq(finalBalance, 0, "vulnerable owner should be emptied");
    }

    /// Protected target: bounded-value permit makes the full-balance drain revert.
    function test_protectedTarget_isBlocked() public {
        (bool drained, uint256 finalBalance) = _runVector(true);
        _report("safe-permit", drained);

        assertFalse(drained, "protected target should not be drainable");
        assertEq(finalBalance, START_BALANCE, "protected owner balance must stay intact");
    }

    // --- signature guards: "BLOCKED" must be earned, not caused by a bad signature ---

    function test_guard_expiredDeadline_reverts() public {
        MockERC20 token = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        vm.warp(1_000);
        uint256 deadline = block.timestamp - 1; // already in the past
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            OWNER_PK, _digest(token, owner, address(spender), type(uint256).max, deadline)
        );

        vm.prank(ATTACKER);
        vm.expectRevert(bytes("ERC20: permit expired"));
        token.permit(owner, address(spender), type(uint256).max, deadline, v, r, s);
    }

    function test_guard_wrongSigner_reverts() public {
        MockERC20 token = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 deadline = block.timestamp + 1 hours;
        // Signed by a different key than `owner` -> recovered != owner.
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(0xB0B, _digest(token, owner, address(spender), type(uint256).max, deadline));

        vm.prank(ATTACKER);
        vm.expectRevert(bytes("ERC20: bad signature"));
        token.permit(owner, address(spender), type(uint256).max, deadline, v, r, s);
    }

    function test_guard_zeroRecover_reverts() public {
        MockERC20 token = new MockERC20();
        MaliciousSpender spender = new MaliciousSpender();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 deadline = block.timestamp + 1 hours;
        // A zeroed signature makes ecrecover return address(0); the guard rejects it.
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("ERC20: bad signature"));
        token.permit(owner, address(spender), type(uint256).max, deadline, 27, bytes32(0), bytes32(0));
    }
}
