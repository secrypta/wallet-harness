// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BlindSigWallet} from "../src/BlindSignVector.sol";

/// @title blind-eth-sign (b) real-incident fixture: legacy eth_sign blind-signing drains.
/// @notice Minimized OFFLINE repro (no live RPC) of the deprecated-but-abused `eth_sign` class.
///         The legacy path signs an opaque 32-byte hash with no displayable structure; drainers
///         used it to obtain blind authorizations. MetaMask MIP-3 (accepted 2024-05-15) removed
///         `eth_sign` (Aug 2024) citing blind-signing phishing risk, and Safe removed it days
///         after the Bybit hack; the EF launched Clear Signing (ERC-7730) in response. The
///         victim blind-signs the raw hash of an attacker-chosen transfer; the attacker replays
///         it and the account is drained. Proof level: class-level (mechanism + deprecation).
///         See PROVENANCE.md.
contract BlindEthSignIncidentTest is Test {
    uint256 constant VICTIM_PK = 0x5EED1C; // placeholder private key for the victim EOA
    address constant ATTACKER = address(0xBAD);
    uint256 constant VICTIM_BALANCE = 300e18;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_ethsignBlindIncident_isDrained() public {
        address victim = vm.addr(VICTIM_PK);
        MockERC20 token = new MockERC20();
        token.mint(victim, VICTIM_BALANCE);

        BlindSigWallet wallet = new BlindSigWallet(victim);
        vm.prank(victim);
        token.approve(address(wallet), type(uint256).max);

        // The phishing page shows the victim an opaque 32-byte hash to "sign in"; the hash is
        // really the authorization for a full-balance transfer to the attacker.
        bytes32 h = keccak256(abi.encode(address(token), ATTACKER, VICTIM_BALANCE));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VICTIM_PK, h);
        wallet.executeBlind(address(token), ATTACKER, VICTIM_BALANCE, v, r, s);

        bool drained = token.balanceOf(ATTACKER) == VICTIM_BALANCE && token.balanceOf(victim) == 0;
        _report("ethsign-blind-victim", drained);

        assertTrue(drained, "blind-signed raw hash should authorize the drain");
        assertEq(token.balanceOf(ATTACKER), VICTIM_BALANCE, "attacker received the full balance");
    }
}
