// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC4337} from "../../vendor/solady-accounts/accounts/ERC4337.sol";

/// @title SoladyErc4337Fixture - concrete ERC-4337 smart account over the UNMODIFIED vendored
///        Solady ERC4337 (account-abstraction) base. Real-safe (tier c) vehicle for the
///        signature-phishing vector.
/// @notice The safety-critical logic - ERC-4337 userOp signature validation
///         (`ERC4337._validateSignature`, which checks the userOp signature against `owner()` via
///         Solady `SignatureCheckerLib`/`ECDSA` with malleability safety) - is unmodified Solady
///         (fixtures/vendor/solady-accounts/, MIT, pinned commit; see fixtures/vendor/PROVENANCE.md).
///         This subclass adds ONLY the required `_domainNameAndVersion` override (the account is
///         otherwise the stock Solady ERC4337, deployed via its canonical `ERC4337Factory`).
///
///         Distinct from the existing signature-phishing holdouts (OZ SignatureChecker EOA path,
///         Solady ERC-1271 contract-signer, OZ ERC2771 meta-tx): this exercises the canonical
///         ACCOUNT-ABSTRACTION userOp-validation surface - a different real verifier wal was never
///         tuned against. A userOp whose signature was forged by an attacker (not the account
///         owner) fails validation, so the bundler/EntryPoint would never execute it and the
///         account's funds are not drained.
contract SoladyErc4337Fixture is ERC4337 {
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        return ("SoladyErc4337Fixture", "1");
    }
}
