// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the upgrade-governance vector (independent codebase).
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
// This mirrors the existing OZ `oz-timelock-safe` fixture but on a DIFFERENT, independent
// implementation: Solady `UUPSUpgradeable` (ERC-1967 upgrade mechanics + onlyProxy/notDelegated
// guards) as the upgrade machinery, with a real OpenZeppelin `TimelockController` as the
// upgrade AUTHORITY. A single compromised key can neither call the upgrade directly (it is not
// the timelock -> `_authorizeUpgrade` reverts) nor shortcut the min-delay. The instant
// single-key implementation swap that the upgrade-governance vector turns on is therefore
// impossible.
//
// The only code authored here on top of the unmodified Solady base is this thin wallet wrapper
// (a one-shot initializer + the `_authorizeUpgrade` override gating on the timelock); it adds
// no bespoke delay logic.

import {UUPSUpgradeable} from "../../../vendor/solady-accounts/utils/UUPSUpgradeable.sol";

interface IERC20Minimal {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title SoladyTimelockUUPSWallet - a Solady-UUPS wallet whose upgrade authority is an
///        OpenZeppelin TimelockController. Implementation v1.
contract SoladyTimelockUUPSWallet is UUPSUpgradeable {
    address public upgradeAuthority; // slot 0 - set to the timelock in the safe configuration
    bool private _initialized;

    function initialize(address upgradeAuthority_) external {
        require(!_initialized, "already initialized");
        _initialized = true;
        upgradeAuthority = upgradeAuthority_;
    }

    /// Solady UUPS hook: only the upgrade authority (the timelock) may authorize a swap. A
    /// compromised single key is not the timelock, so a direct instant upgrade reverts here.
    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == upgradeAuthority, "upgrade: not authorized");
    }

    function version() external pure virtual returns (uint256) {
        return 1;
    }

    function balance(address token) external view returns (uint256) {
        return IERC20Minimal(token).balanceOf(address(this));
    }
}

/// @title SoladyTimelockUUPSWalletV2 - a legitimate new implementation, used to prove the
///        timelock-governed upgrade path still works (BLOCKED is not vacuous).
contract SoladyTimelockUUPSWalletV2 is SoladyTimelockUUPSWallet {
    function version() external pure override returns (uint256) {
        return 2;
    }
}

/// @title SoladyDrainUpgradeImpl - the hostile implementation an attacker would swap in. A
///        valid UUPS implementation (so the swap would not fail for any unrelated reason); its
///        `sweep` empties the wallet. The fixture's point: the swap is rejected at
///        authorization time, so `sweep` is never reachable.
contract SoladyDrainUpgradeImpl is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}

    function sweep(address token, address attacker) external {
        uint256 bal = IERC20Minimal(token).balanceOf(address(this));
        IERC20Minimal(token).transfer(attacker, bal);
    }

    function version() external pure returns (uint256) {
        return 666;
    }
}
