// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC4337} from "../../vendor/solady-accounts/accounts/ERC4337.sol";

// -----------------------------------------------------------------------------
// Fixture provenance (see ./solady-erc4337-executor-safe/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: c-safe-impl   Expected: BLOCKED
//   Nature:  Concrete ERC-4337 smart account over the UNMODIFIED vendored Solady ERC4337
//            (account-abstraction) base (fixtures/vendor/solady-accounts/, MIT, pinned commit;
//            see fixtures/vendor/PROVENANCE.md). The safety-critical logic - the arbitrary
//            external-call sink `execute(target,value,data)` gated by the `onlyEntryPointOrOwner`
//            modifier - is unmodified Solady. This subclass adds ONLY the required
//            `_domainNameAndVersion` override. No logic authored here.
//   Why safe for malicious-calldata: `execute`/`executeBatch` are exactly the arbitrary-call
//            shape the vector abuses (Socket/LI.FI/Rubic 2022-2024: a contract runs a
//            caller-supplied target+calldata against a standing approval). It is safe not
//            because the sink is absent but because reaching it is GATED: the caller must be
//            the canonical ERC-4337 EntryPoint (which only forwards an owner-signed, validated
//            UserOperation) or the account owner. An attacker who is neither cannot inject
//            `transferFrom(victim, attacker, ...)` or sweep the account - the call reverts
//            `Unauthorized()`.
//   Distinct from the other malicious-calldata c-safe fixtures (oz-multicall self-atomic batch,
//            oz-timelock-executor role+min-delay, solady-multicallable, solady-ownableroles-
//            executor role-gated, simulated-exec): this is the ACCOUNT-ABSTRACTION gate
//            (EntryPoint-or-owner), a different real mechanism. Also distinct from the
//            signature-phishing ERC-4337 holdout: that exercises userOp signature VALIDATION;
//            this exercises arbitrary-external-call INJECTION against the gated executor.
//   License: vendored Solady = MIT (Copyright Solady authors); this wrapper = MIT (this repo).
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @title SoladyErc4337Executor - concrete Solady ERC-4337 account; real-safe (tier c) vehicle
///        for the malicious-calldata vector (gated arbitrary-external-call executor).
contract SoladyErc4337Executor is ERC4337 {
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        return ("SoladyErc4337Executor", "1");
    }
}
