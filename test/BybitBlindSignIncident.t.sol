// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {BlindMultisigWallet} from "../fixtures/blind-eth-sign/b-incident/BlindMultisigWallet.sol";

/// @title blind-eth-sign (b) real-incident fixture: Bybit / Safe multisig blind-signing
///        theft (2025-02-21).
/// @notice Minimized OFFLINE replay of the signing defect behind the ~$1.5B Bybit theft:
///         three multisig owners approved a transaction digest their hardware wallets could
///         not decode (blind signing), and that authorization executed an operation that
///         swept the wallet. The real operation (Safe execTransaction, selector 0x6a761202,
///         tx 0x46deef...7882) delegatecalled a malicious contract that overwrote the Safe
///         singleton and then swept ETH/ERC-20; here we model the blind-signed-authorization
///         -> drain ESSENCE (the signing surface this vector is about), with the authorized
///         operation being a direct transfer of the wallet's balance to the attacker. The
///         owners are key-derived stand-ins (real owner keys are not public). The verdict is
///         derived from the real outcome (the wallet's balance left to the attacker).
contract BybitBlindSignIncidentTest is Test {
    // Three owner keys (stand-ins: the real Bybit signer keys are not public).
    uint256 constant OWNER_PK_1 = 0xB1B17001;
    uint256 constant OWNER_PK_2 = 0xB1B17002;
    uint256 constant OWNER_PK_3 = 0xB1B17003;
    address constant ATTACKER = address(0xBDd077); // the malicious beneficiary (stand-in)
    uint256 constant VAULT_BALANCE = 100 ether; // stands in for the cold-wallet balance

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat("[blind-eth-sign] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED")
        );
    }

    function test_bybitBlindSignIncident_isDrained() public {
        // Owners sorted ascending by address (as the wallet requires for the signature blob).
        (uint256[3] memory pks, address[3] memory addrs) = _sortedOwners();
        address[] memory owners = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            owners[i] = addrs[i];
        }

        BlindMultisigWallet wallet = new BlindMultisigWallet(owners, 3);
        vm.deal(address(wallet), VAULT_BALANCE);

        // The attacker-crafted operation the owners are tricked into blind-signing: move the
        // wallet's entire balance to the attacker. On a hardware wallet that cannot decode the
        // payload, the signers see only the opaque 32-byte txHash below.
        address to = ATTACKER;
        uint256 value = VAULT_BALANCE;
        bytes memory data = "";
        bytes32 txHash = wallet.getTransactionHash(to, value, data, wallet.nonce());

        // All three owners blind-sign the opaque digest, in ascending signer-address order.
        bytes memory signatures;
        for (uint256 i = 0; i < 3; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], txHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }

        uint256 attackerBefore = ATTACKER.balance;

        // The attacker submits the signed operation; the wallet drains.
        wallet.execTransaction(to, value, data, signatures);

        bool drained = (address(wallet).balance == 0 && ATTACKER.balance == attackerBefore + VAULT_BALANCE);
        _report("bybit-blind-sign-victim", drained);

        assertTrue(drained, "blind-signed operation should drain the wallet to the attacker");
        assertEq(address(wallet).balance, 0, "cold wallet emptied");
    }

    /// @dev Returns owner (pk, addr) pairs sorted ascending by address.
    function _sortedOwners() internal view returns (uint256[3] memory pks, address[3] memory addrs) {
        pks = [OWNER_PK_1, OWNER_PK_2, OWNER_PK_3];
        for (uint256 i = 0; i < 3; i++) {
            addrs[i] = vm.addr(pks[i]);
        }
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
    }
}
