// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the create2-metamorphic vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
//
// Solady `CREATE3` is the canonical CREATE3 deterministic-deployment library. The deployed
// address depends ONLY on (salt, deployer) - it is INDEPENDENT of the init code. A tiny CREATE2
// proxy is placed at the deterministic slot and then `CREATE`s the target; neither has a
// `selfdestruct`. Once a contract is deployed at the deterministic address it can never be
// destroyed and redeployed, and a second deploy at the same salt reverts (the proxy slot is
// occupied). The metamorphic precondition (redeploy DIFFERENT code at the SAME address that a
// prior approval points at) is therefore absent.
//
// This fixture is a PRECISION check and is DISTINCT from the EIP-1167-clone fixtures
// (`solady-libclone-safe`, `oz-clones-safe`, `codehash-pinned-safe`): CREATE3 derives the
// address from salt+deployer rather than from the init code, so a second deploy at the same
// salt (even with different code) targets the SAME address and still fails. The only authored
// code is this thin factory wrapper over the unmodified Solady `CREATE3`.

import {CREATE3} from "../../../vendor/solady-accounts/utils/CREATE3.sol";

/// @title Create3Factory - deterministic CREATE3 factory over the unmodified Solady library.
contract Create3Factory {
    /// @notice Deploy `initCode` at a CREATE3 address derived from (salt, this factory).
    function deployDeterministic(bytes memory initCode, bytes32 salt) external returns (address) {
        return CREATE3.deployDeterministic(initCode, salt);
    }

    /// @notice The CREATE3 address for `salt` under this factory - independent of init code.
    function predict(bytes32 salt) external view returns (address) {
        return CREATE3.predictDeterministicAddress(salt, address(this));
    }
}

/// @title PingImpl - the first, "approved" code deployed at the deterministic address.
contract PingImpl {
    function ping() external pure returns (uint256) {
        return 42;
    }
}

/// @title EvilImpl - different code an attacker would try to place at the same address.
contract EvilImpl {
    function drain() external pure returns (uint256) {
        return 0xdead;
    }
}
