// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Odos limit-order-router signature-validation drain
// (2025-01-23, Base, ~$50K per OpenZeppelin). Authored in THIS repo (MIT). NOT a copy of the
// on-chain OdosLimitOrderRouter and NOT a copy of any third-party PoC. The documented MECHANISM
// is reproduced from authoritative write-ups; see ./odos-erc6492-victim/PROVENANCE.md for incident
// facts (attacker, tx hash, sources) and the DeFiHackLabs reference used to locate them.
//
// Root cause (per OpenZeppelin / QuillAudits): the router validated ERC-6492 "predeploy"
// signatures by INHERITING the ERC-6492 reference `UniversalSigValidator` logic into the router
// itself instead of deploying it as a separate contract and calling it. In the counterfactual
// branch (signer not yet deployed) the reference logic low-level-calls a factory using a
// `create2Factory` address and `factoryCalldata` that BOTH come from the attacker-supplied
// signature - an arbitrary call executed inside signature validation. The attacker set the signer
// to the identity precompile `0x04` (which has no code) to force the deploy branch, turning sig
// validation into an attacker-chosen call from the router's context.
//
// R15 anchor axis (iii): ERC-6492 counterfactual deploy-and-trust - a caller-supplied factory is
// low-level-called with caller-supplied calldata during validation, then the (attacker-named)
// signer's isValidSignature is trusted. Offline fixture, never deployed.

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

contract OdosLimitOrderRouterClone {
    bytes4 private constant MAGIC = 0x1626ba7e;

    /// @notice ERC-6492-style validation. `signature` is the attacker-supplied wrapper carrying
    ///         the signer, the counterfactual factory, its calldata, and the inner signature.
    function isValidSigImpl(bytes32 hash, bytes calldata signature) public returns (bytes4) {
        (address signer, address factory, bytes memory factoryCalldata, bytes memory inner) =
            abi.decode(signature, (address, address, bytes, bytes));

        if (signer.code.length == 0) {
            // Counterfactual deploy: factory AND factoryCalldata are attacker-controlled -> this
            // is an arbitrary call from the router during signature validation.
            (bool ok, ) = factory.call(factoryCalldata);
            require(ok, "deploy failed");
        }

        // Trust the (attacker-named) signer's attestation.
        return IERC1271(signer).isValidSignature(hash, inner);
    }
}
