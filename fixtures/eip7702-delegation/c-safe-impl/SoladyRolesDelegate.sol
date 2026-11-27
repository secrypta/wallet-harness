// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OwnableRoles} from "../../vendor/solady-accounts/auth/OwnableRoles.sol";

/// @title SoladyRolesDelegate - a 7702-delegate account whose arbitrary-call execution is gated by
///        Solady's role system. Real-safe (tier c) vehicle for the eip7702-delegation vector.
/// @notice Under EIP-7702, the delegate can `execute` arbitrary calls for the EOA; safe designs
///         restrict WHO may trigger execution. Here that gate is unmodified Solady `OwnableRoles`
///         (fixtures/vendor/solady-accounts/auth/OwnableRoles.sol, MIT, pinned commit; see
///         fixtures/vendor/PROVENANCE.md): only the owner, or an address the owner granted the
///         `EXECUTOR_ROLE` to, can execute; any other caller reverts `Unauthorized`. This contract
///         adds ONLY a one-time `initialize`, a role constant and the role-gated `execute`.
///
///         Distinct from the existing eip7702 holdouts: `oz-accesscontrol-exec-safe` uses
///         OpenZeppelin `AccessControl` (different codebase), `solady-erc7821-safe` uses plain
///         `Ownable`, and `solady-initguard-safe` tests init-time auth. This exercises Solady's
///         independent BITMASK role system (a different real authorization mechanism wal was never
///         tuned against).
contract SoladyRolesDelegate is OwnableRoles {
    /// @dev The single role permitted to trigger execution (Solady roles are a bitmask).
    uint256 public constant EXECUTOR_ROLE = _ROLE_0;

    function initialize(address owner_) external {
        _initializeOwner(owner_);
    }

    /// @notice Execute an arbitrary call - the delegate's power under 7702. Gated by Solady's
    ///         `onlyRolesOrOwner`: only the owner or an EXECUTOR_ROLE holder may call it.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        onlyRolesOrOwner(EXECUTOR_ROLE)
        returns (bytes memory result)
    {
        bool ok;
        (ok, result) = target.call{value: value}(data);
        require(ok, "execute failed");
    }

    receive() external payable {}
}
