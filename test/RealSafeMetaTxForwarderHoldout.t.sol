// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ERC2771Forwarder} from "../fixtures/vendor/oz/metatx/ERC2771Forwarder.sol";
import {MetaTxForwarderVault} from
    "../fixtures/signature-phishing/c-safe-impl/MetaTxForwarderVault.sol";

/// @title Tier-(c) real-safe HOLDOUT for signature-phishing: OpenZeppelin ERC2771 meta-tx forwarder.
/// @notice A gasless meta-transaction sub-vector: a relayer submits a `ForwardRequest` the user
///         signed off-chain, and the recipient attributes the call to that signer. The binding
///         that stops a forged request from impersonating the victim is the UNMODIFIED OZ v5.1.0
///         `ERC2771Forwarder` EIP-712 signature verification. A request forged by the attacker
///         (signed with the attacker key but claiming `from = victim`) is rejected
///         (`ERC2771ForwarderInvalidSigner`), so the relayed drain never runs and the vault keeps
///         the victim's funds -> the harness MUST stay silent (verdict BLOCKED, label safe). A
///         guard proves a genuine victim-signed request DOES execute, so BLOCKED is a real
///         rejection, not a broken relay. split=holdout; verdict derived from the real outcome.
contract RealSafeMetaTxForwarderHoldoutTest is Test {
    uint256 constant VICTIM_PK = 0xA11CE;
    uint256 constant ATTACKER_PK = 0xBAD5EA;
    address constant ATTACKER = address(0xA77ACC);
    string constant FWD_NAME = "MetaTxForwarder";
    uint256 constant START_BALANCE = 100e18;

    bytes32 constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,uint48 deadline,bytes data)"
    );

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function _domainSeparator(address forwarder) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(FWD_NAME)),
                keccak256(bytes("1")),
                block.chainid,
                forwarder
            )
        );
    }

    function _digest(
        address forwarder,
        address from,
        address to,
        uint256 value,
        uint256 gas,
        uint256 nonce,
        uint48 deadline,
        bytes memory data
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(FORWARD_REQUEST_TYPEHASH, from, to, value, gas, nonce, deadline, keccak256(data))
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(forwarder), structHash));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _setup()
        internal
        returns (MockERC20 token, ERC2771Forwarder fwd, MetaTxForwarderVault vault, address victim)
    {
        victim = vm.addr(VICTIM_PK);
        token = new MockERC20();
        fwd = new ERC2771Forwarder(FWD_NAME);
        vault = new MetaTxForwarderVault(address(fwd), address(token));
        token.mint(address(vault), START_BALANCE);
        vault.fund(victim, START_BALANCE);
    }

    function test_sigPhishing_metaTxForwarder_blocked() public {
        (MockERC20 token, ERC2771Forwarder fwd, MetaTxForwarderVault vault, address victim) = _setup();

        uint48 deadline = uint48(block.timestamp + 1 hours);
        bytes memory drain = abi.encodeWithSelector(MetaTxForwarderVault.withdraw.selector, ATTACKER, START_BALANCE);

        // Phisher forges a request claiming from=victim, but signs it with their OWN key.
        bytes32 digest = _digest(address(fwd), victim, address(vault), 0, 500000, fwd.nonces(victim), deadline, drain);
        bytes memory forgedSig = _sign(ATTACKER_PK, digest);

        ERC2771Forwarder.ForwardRequestData memory req = ERC2771Forwarder.ForwardRequestData({
            from: victim,
            to: address(vault),
            value: 0,
            gas: 500000,
            deadline: deadline,
            data: drain,
            signature: forgedSig
        });

        vm.prank(ATTACKER);
        try fwd.execute(req) {} catch {}

        bool drained = (token.balanceOf(address(vault)) < START_BALANCE) || token.balanceOf(ATTACKER) > 0;
        _report("oz-erc2771-forwarder-safe", drained);

        assertFalse(drained, "a forged meta-tx request must not drain the victim's vault balance");
        assertEq(token.balanceOf(address(vault)), START_BALANCE, "vault balance intact");
        assertEq(token.balanceOf(ATTACKER), 0, "attacker gets nothing");
        assertEq(vault.balanceOf(victim), START_BALANCE, "victim ledger balance intact");
    }

    /// Guard: a genuine victim-signed request DOES execute - so BLOCKED above is a real rejection
    /// of the forged signature, not a broken relay.
    function test_guard_genuineRequest_executes() public {
        (MockERC20 token, ERC2771Forwarder fwd, MetaTxForwarderVault vault, address victim) = _setup();
        address dest = address(0xC0FFEE);

        uint48 deadline = uint48(block.timestamp + 1 hours);
        bytes memory data = abi.encodeWithSelector(MetaTxForwarderVault.withdraw.selector, dest, 10e18);

        bytes32 digest = _digest(address(fwd), victim, address(vault), 0, 500000, fwd.nonces(victim), deadline, data);
        bytes memory sig = _sign(VICTIM_PK, digest);

        ERC2771Forwarder.ForwardRequestData memory req = ERC2771Forwarder.ForwardRequestData({
            from: victim,
            to: address(vault),
            value: 0,
            gas: 500000,
            deadline: deadline,
            data: data,
            signature: sig
        });

        // Anyone may relay a validly-signed request.
        vm.prank(ATTACKER);
        fwd.execute(req);

        assertEq(token.balanceOf(dest), 10e18, "genuine victim-signed meta-tx should execute");
        assertEq(vault.balanceOf(victim), START_BALANCE - 10e18, "only the signed amount moved from the victim");
    }
}
