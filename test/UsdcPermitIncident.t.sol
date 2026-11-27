// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {USDCPermitClone} from "../fixtures/permit-phishing/b-incident/USDCPermitClone.sol";

/// @title permit-phishing (b) real-incident fixture: USDC ERC-2612 permit drain (2026-03-16).
/// @notice Minimized OFFLINE replay of the documented path (no live RPC): the victim signs
///         an off-chain permit with value = MAX_UINT256 and never-expiring deadline, the
///         attacker's spender contract submits `permit` to set the allowance, then
///         `transferFrom`'s the balance out - the one-tx drain pattern. The real attacker
///         and spender addresses from the public write-up are used as-is. The permit OWNER
///         is a key-derived stand-in: EIP-2612 requires a valid signature, and the real
///         victim's private key is (rightly) not public, so we cannot sign as the real
///         address. This preserves the mechanism faithfully; the real victim address is
///         cited in PROVENANCE.md. The verdict is derived from the real outcome.
contract UsdcPermitIncidentTest is Test {
    // Public, documented addresses (darknavy.org write-up + Etherscan).
    address constant ATTACKER = 0xAfb2423F447D3e16931164C9970B9741aAb1723E;
    address constant SPENDER = 0x0927BA1f2A31875b0Dd7b28eEC3A3E74B4620653; // permit spender / drainer

    uint256 constant OWNER_PK = 0xC0DE; // stand-in signer (real victim key is not public)
    // Representative balance: the incident drained 1,766,308.43 USDC (6 decimals).
    uint256 constant VICTIM_BALANCE = 1_766_308_430000;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_usdcPermitIncident_isDrained() public {
        USDCPermitClone token = new USDCPermitClone();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, VICTIM_BALANCE);

        // Off-chain permit the victim was phished into signing: value = MAX, deadline = never.
        uint256 value = type(uint256).max;
        uint256 deadline = type(uint256).max;
        bytes32 structHash =
            keccak256(abi.encode(token.PERMIT_TYPEHASH(), owner, SPENDER, value, token.nonces(owner), deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        // Drain tx 0xfd7417...a642: spender submits permit, then transferFrom empties the owner.
        vm.startPrank(SPENDER);
        token.permit(owner, SPENDER, value, deadline, v, r, s);
        uint256 balanceBefore = token.balanceOf(owner);
        token.transferFrom(owner, ATTACKER, balanceBefore);
        vm.stopPrank();

        uint256 finalBalance = token.balanceOf(owner);
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("usdc-permit-victim", drained);

        assertTrue(drained, "incident replay should drain the victim");
        assertEq(finalBalance, 0, "victim should be emptied");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker should hold the drained balance");
    }
}
