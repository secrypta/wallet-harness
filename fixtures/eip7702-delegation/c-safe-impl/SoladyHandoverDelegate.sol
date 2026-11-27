// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "../../vendor/solady-accounts/auth/Ownable.sol";

/// @title SoladyHandoverDelegate - a 7702-delegate account whose ownership (and thus execution
///        authority) can only be taken over through Solady's TWO-STEP ownership handover. Real-safe
///        (tier c) vehicle for the eip7702-delegation vector.
/// @notice A real 7702 hijack path is an attacker trying to seize the delegate's owner slot and
///         then drain. Solady `Ownable` (unmodified; fixtures/vendor/solady-accounts/auth/Ownable.sol,
///         MIT, pinned commit; see fixtures/vendor/PROVENANCE.md) makes that impossible in one step:
///         `transferOwnership`/`completeOwnershipHandover` are `onlyOwner`, and
///         `requestOwnershipHandover` merely registers a pending request that the CURRENT owner
///         must complete. An attacker cannot unilaterally become owner, so they cannot reach the
///         owner-gated `execute`. This contract adds ONLY a one-time `initialize` and the
///         owner-gated `execute`.
///
///         Distinct from the existing eip7702 holdouts: `solady-initguard-safe` tests init-time
///         auth (reinit), `solady-ownableroles-exec-safe` tests role-gated execution, and the
///         others test call-time owner/role checks. This exercises a different security PROPERTY -
///         the two-step ownership-handover takeover defense on real Solady code.
contract SoladyHandoverDelegate is Ownable {
    function initialize(address owner_) external {
        _initializeOwner(owner_);
    }

    /// @notice Execute an arbitrary call - the delegate's power under 7702. `onlyOwner`.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyOwner
        returns (bytes memory result)
    {
        bool ok;
        (ok, result) = target.call{value: value}(data);
        require(ok, "execute failed");
    }

    receive() external payable {}
}
