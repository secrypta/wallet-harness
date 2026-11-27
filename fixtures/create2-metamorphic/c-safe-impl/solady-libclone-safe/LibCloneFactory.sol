// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the create2-metamorphic vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
// Solady `LibClone.cloneDeterministic` is the canonical CREATE2 minimal-proxy deployer. The
// deployed clone is a fixed minimal-proxy: it has NO `selfdestruct`, so the code at its
// deterministic address can never be destroyed and redeployed as different code. The
// metamorphic precondition (CREATE2 + SELFDESTRUCT + redeploy at the same address, which a
// prior approval would then point at hostile logic) is therefore absent. This fixture is a
// PRECISION check: legitimate, ubiquitous CREATE2 usage (immutable clones) must NOT be flagged.
//
// The only code authored here on top of the unmodified Solady base is this thin factory wrapper.

import {LibClone} from "../../../vendor/solady-accounts/utils/LibClone.sol";

/// @title LibCloneFactory - deterministic clone factory over the unmodified Solady LibClone.
contract LibCloneFactory {
    /// @notice Deploy a minimal-proxy clone of `implementation` at a deterministic address.
    function deployDeterministic(address implementation, bytes32 salt) external returns (address) {
        return LibClone.cloneDeterministic(implementation, salt);
    }

    /// @notice The address the clone will occupy - pre-computable, independent of nonce.
    function predict(address implementation, bytes32 salt) external view returns (address) {
        return LibClone.predictDeterministicAddress(implementation, salt, address(this));
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
