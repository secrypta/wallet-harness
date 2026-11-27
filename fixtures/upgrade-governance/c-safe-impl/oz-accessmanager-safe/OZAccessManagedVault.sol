// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the upgrade-governance vector.
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// OZ `AccessManager` is the canonical role-and-delay authority: `canCall(caller, target,
// selector)` returns whether `caller` may invoke `selector` on `target` right now
// (`immediate`) and any required execution `delay`. The upgrade-governance vector
// (Audius-style) is a single key instantly swapping a protected implementation/admin
// parameter. Here the sensitive admin operation is gated by `AccessManager.canCall`:
//   * a key with NO granted role is rejected (`immediate == false`);
//   * a key whose role carries an execution delay is ALSO rejected for a direct call
//     (`immediate == false`, `delay > 0`) - it must route through the manager's scheduled
//     `execute`, so there is no instant single-key swap.
//
// The ONLY code authored here is this thin managed vault: it stores the manager (`authority`)
// and a protected `implementation` pointer, and enforces the real OZ decision by requiring
// `authority.canCall(...).immediate`. The authorization logic itself (roles, delays,
// scheduling) is entirely OpenZeppelin's unmodified `AccessManager`.

import {IAccessManager} from "../../../vendor/oz/access/manager/IAccessManager.sol";

/// @title OZAccessManagedVault - an admin-gated vault whose sensitive op defers to OZ AccessManager.
contract OZAccessManagedVault {
    address public immutable authority; // the OZ AccessManager
    address public implementation; // the governance-protected pointer (the "upgrade" target)

    constructor(address authority_) {
        authority = authority_;
        implementation = address(this);
    }

    /// @dev Enforce the UNMODIFIED OZ AccessManager decision: only an immediately-authorized
    ///      caller passes; no role, or a delayed role, is rejected for a direct call.
    function _restricted() internal view {
        (bool immediate,) = IAccessManager(authority).canCall(msg.sender, address(this), msg.sig);
        require(immediate, "AccessManaged: unauthorized");
    }

    /// @notice The sensitive governance operation (instant single-key swap must be impossible).
    function setImplementation(address impl) external {
        _restricted();
        implementation = impl;
    }
}

/// @title BenignImpl / HostileImpl - distinct pointers used by the test (the vector is whether
///        an unauthorized key can swap the protected `implementation` instantly).
contract BenignImpl {
    function tag() external pure returns (uint256) {
        return 1;
    }
}

contract HostileImpl {
    function tag() external pure returns (uint256) {
        return 0xdead;
    }
}
