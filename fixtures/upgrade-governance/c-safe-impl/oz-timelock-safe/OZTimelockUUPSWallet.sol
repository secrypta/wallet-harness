// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the upgrade-governance vector (R10').
//
// The safety-relevant machinery exercised here is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts  (tag v5.1.0, commit 69c8def5)
//   license: MIT  (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
// - UUPSUpgradeable enforces that an implementation swap can only happen through the proxy
//   and only if `_authorizeUpgrade` passes (ERC-1967 upgrade mechanics unchanged).
// - TimelockController is the upgrade AUTHORITY (the wallet's `owner`), so an upgrade is a
//   scheduled, min-delay, two-step governance action - a single compromised key can neither
//   call the upgrade directly nor shortcut the delay.
//
// The only code authored here on top of the unmodified OZ base is the thin wallet wrapper
// below: a one-shot `initialize(owner)` and the `_authorizeUpgrade` override that gates the
// upgrade on the owner (the timelock). It adds no bespoke delay logic - the delay/guardian
// guarantee comes entirely from the real OZ TimelockController.

import {UUPSUpgradeable} from "../../../vendor/oz/proxy/utils/UUPSUpgradeable.sol";

interface IERC20Minimal {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title OZTimelockUUPSWallet - a UUPS-upgradeable wallet whose upgrade authority is an
///        OpenZeppelin TimelockController. Implementation v1.
contract OZTimelockUUPSWallet is UUPSUpgradeable {
    /// The single upgrade authority. In the safe configuration this is the address of an
    /// OZ TimelockController, so "the owner" is a delay+role gated contract, not an EOA.
    address public upgradeAuthority;
    bool private _initialized;

    /// One-shot initializer, run via the proxy's constructor (ERC1967Proxy `_data`).
    function initialize(address upgradeAuthority_) external {
        require(!_initialized, "already initialized");
        _initialized = true;
        upgradeAuthority = upgradeAuthority_;
    }

    /// UUPS hook: only the upgrade authority (the timelock) may authorize a swap. A
    /// compromised single key is not the timelock, so a direct instant upgrade reverts here.
    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == upgradeAuthority, "upgrade: not authorized");
    }

    function version() external pure virtual returns (uint256) {
        return 1;
    }

    /// Read-only helper for the test to confirm funds never moved.
    function balance(address token) external view returns (uint256) {
        return IERC20Minimal(token).balanceOf(address(this));
    }
}

/// @title OZTimelockUUPSWalletV2 - a legitimate new implementation, used to prove the
///        timelock-governed upgrade path still works (BLOCKED is not vacuous).
contract OZTimelockUUPSWalletV2 is OZTimelockUUPSWallet {
    function version() external pure override returns (uint256) {
        return 2;
    }
}

/// @title DrainUpgradeImpl - the hostile implementation an attacker would swap in. It is a
///        valid UUPS implementation (so the swap would NOT fail for any unrelated reason),
///        and its `sweep` empties the wallet. The point of the fixture is that the swap is
///        rejected at authorization time, so `sweep` is never reachable.
contract DrainUpgradeImpl is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}

    function sweep(address token, address attacker) external {
        uint256 bal = IERC20Minimal(token).balanceOf(address(this));
        IERC20Minimal(token).transfer(attacker, bal);
    }
}
