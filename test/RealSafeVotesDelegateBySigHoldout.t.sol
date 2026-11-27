// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OzVotesTokenFixture} from "../fixtures/blind-eth-sign/c-safe-impl/OzVotesTokenFixture.sol";

/// @title Tier-(c) real-safe HOLDOUT for blind-eth-sign: OpenZeppelin Votes.delegateBySig.
/// @notice `delegateBySig` redirects an account's voting power from an off-chain signature; the
///         signature must cover the FULLY-TYPED EIP-712 Delegation digest (unmodified OZ v5.1.0).
///         A blind eth_sign (personal_sign over an opaque hash) does not cover that typed digest,
///         so ECDSA.recover yields a signer other than the victim and the victim's voting power
///         cannot be redirected to the phisher -> the harness MUST stay silent (verdict BLOCKED,
///         label safe). A guard proves a genuine typed Delegation signature DOES delegate, so
///         BLOCKED is a real rejection, not broken delegation. split=holdout; verdict from the
///         real outcome.
contract RealSafeVotesDelegateBySigHoldoutTest is Test {
    uint256 constant VICTIM_PK = 0xA11CE;
    address constant ATTACKER = address(0xA77ACC);
    uint256 constant VOTES = 1_000e18;

    bytes32 constant DELEGATION_TYPEHASH =
        keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function _domainSeparator(address tok) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Gov Token")),
                keccak256(bytes("1")),
                block.chainid,
                tok
            )
        );
    }

    function _delegationDigest(address tok, address delegatee, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(tok), structHash));
    }

    function test_blindEthSign_votesDelegateBySig_blocked() public {
        OzVotesTokenFixture tok = new OzVotesTokenFixture();
        address victim = vm.addr(VICTIM_PK);
        tok.mint(victim, VOTES);

        // Victim self-delegates (so their balance counts as votes held under their own control).
        vm.prank(victim);
        tok.delegate(victim);
        assertEq(tok.getVotes(victim), VOTES, "victim holds their own votes");

        // Phisher tricks the victim into a BLIND eth_sign over an opaque 32-byte hash, then tries
        // to use it as a delegateBySig that redirects the victim's votes to the attacker.
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 typedDigest = _delegationDigest(address(tok), ATTACKER, 0, expiry);
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedDigest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VICTIM_PK, ethSigned);

        // The blind signature recovers to some address that is NOT the victim; it cannot move the
        // victim's delegation. (Call may succeed for the junk recovered signer - that is harmless.)
        try tok.delegateBySig(ATTACKER, 0, expiry, v, r, s) {} catch {}

        bool drained = (tok.getVotes(ATTACKER) >= VOTES) || (tok.delegates(victim) != victim);
        _report("oz-votes-delegatebysig-safe", drained);

        assertFalse(drained, "a blind signature must not redirect the victim's voting power");
        assertEq(tok.getVotes(ATTACKER), 0, "attacker gains none of the victim's votes");
        assertEq(tok.delegates(victim), victim, "victim's delegation is unchanged");
        assertEq(tok.getVotes(victim), VOTES, "victim keeps their voting power");
    }

    /// Guard: a genuine TYPED Delegation signature DOES delegate - so BLOCKED above is a real
    /// rejection of the blind-signed path, not broken delegation.
    function test_guard_typedDelegation_delegates() public {
        OzVotesTokenFixture tok = new OzVotesTokenFixture();
        address victim = vm.addr(VICTIM_PK);
        tok.mint(victim, VOTES);

        address chosen = address(0xC0FFEE);
        uint256 expiry = block.timestamp + 1 hours;
        bytes32 digest = _delegationDigest(address(tok), chosen, 0, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VICTIM_PK, digest);

        tok.delegateBySig(chosen, 0, expiry, v, r, s);

        assertEq(tok.delegates(victim), chosen, "a genuine typed Delegation signature should delegate");
        assertEq(tok.getVotes(chosen), VOTES, "the chosen delegatee receives the victim's votes");
    }
}
