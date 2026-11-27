// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "../../vendor/solady-accounts/auth/Ownable.sol";

/// @title SoladyInitGuardDelegate - a 7702-delegate account with Solady's initialization-hijack
///        defense. Real-safe (tier c) vehicle for the eip7702-delegation vector.
/// @notice Under EIP-7702, an EOA delegates its code to an account implementation that can
///         `execute` arbitrary calls on the EOA's behalf. A real footgun is the INITIALIZATION
///         HIJACK: if ownership can be (re-)initialized by anyone, an attacker seizes the
///         delegate and drains the account. This vehicle sets ownership through Solady's
///         UNMODIFIED `Ownable._initializeOwner` and opts into Solady's re-initialization guard
///         by overriding `_guardInitializeOwner()` to return true - so a second `initialize`
///         reverts `AlreadyInitialized`, and only the owner set at first initialization can
///         `execute`. The safety-critical logic (the init guard and the `onlyOwner` check) is
///         unmodified Solady (fixtures/vendor/solady-accounts/auth/Ownable.sol, MIT, pinned
///         commit; see fixtures/vendor/PROVENANCE.md); this contract adds ONLY the thin
///         `initialize` entrypoint and an owner-gated `execute`.
///
///         Distinct from the existing eip7702 holdouts: `solady-erc7821-safe` and
///         `oz-accesscontrol-exec-safe` test CALL-TIME authorization (non-owner / non-role batch
///         or call reverts). This fixture tests INIT-TIME authorization - the reinit-hijack
///         defense - a different property, on real Solady code wal was never tuned against.
contract SoladyInitGuardDelegate is Ownable {
    /// @dev Opt into Solady's re-initialization guard: once initialized, `initialize` reverts.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /// @notice One-time initialization of the delegate's owner (e.g. the authorizing EOA).
    ///         A second call reverts `AlreadyInitialized` via Solady's guard - an attacker cannot
    ///         re-initialize to seize the account.
    function initialize(address owner_) external {
        _initializeOwner(owner_);
    }

    /// @notice Execute an arbitrary call on the account's behalf - the delegate's power under
    ///         7702. Gated by Solady's `onlyOwner`: a non-owner caller reverts `Unauthorized`.
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
