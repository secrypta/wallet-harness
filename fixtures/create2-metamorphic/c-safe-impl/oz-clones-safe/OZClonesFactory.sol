// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the create2-metamorphic vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// OZ `Clones.cloneDeterministic` is the canonical CREATE2 minimal-proxy (EIP-1167) deployer,
// used across the ecosystem for factory patterns. The deployed clone is a fixed minimal
// proxy: it has NO `selfdestruct`, so the code at its deterministic address can never be
// destroyed and redeployed as different code. The metamorphic precondition (CREATE2 +
// SELFDESTRUCT + redeploy DIFFERENT code at the SAME address, which a prior approval would
// then point at hostile logic) is therefore absent. Additionally, OZ bakes the implementation
// address into the clone's init code, so a different implementation derives a DIFFERENT
// address - it can never occupy the approved clone's slot.
//
// This fixture is a PRECISION check: ubiquitous, legitimate CREATE2 usage (immutable clones)
// must NOT be flagged as a metamorphic-swap risk. The only code authored here is this thin
// factory wrapper over the unmodified OZ `Clones` library.

import {Clones} from "../../../vendor/oz/proxy/Clones.sol";

/// @title OZClonesFactory - deterministic clone factory over the unmodified OZ Clones library.
contract OZClonesFactory {
    /// @notice Deploy a minimal-proxy clone of `implementation` at a deterministic address.
    function deployDeterministic(address implementation, bytes32 salt) external returns (address) {
        return Clones.cloneDeterministic(implementation, salt);
    }

    /// @notice The address the clone will occupy - pre-computable, independent of nonce.
    function predict(address implementation, bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(implementation, salt, address(this));
    }
}

/// @title PingImpl - a trivial implementation to clone (first, "approved" code).
contract PingImpl {
    function ping() external pure returns (uint256) {
        return 42;
    }
}

/// @title EvilImpl - a different implementation an attacker would try to redeploy at the same
///        deterministic address. The point of the fixture is that the redeploy is impossible.
contract EvilImpl {
    function drain() external pure returns (uint256) {
        return 0xdead;
    }
}
