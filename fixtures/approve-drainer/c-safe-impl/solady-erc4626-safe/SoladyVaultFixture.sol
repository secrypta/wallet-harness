// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC4626} from "../../../vendor/solady-accounts/tokens/ERC4626.sol";

/// @title SoladyVaultFixture - concrete vault over the UNMODIFIED Solady ERC4626.
/// @notice Tier-(c) real-safe HOLDOUT vehicle for approve-drainer. The share token is Solady's
///         ERC-4626 (fixtures/vendor/solady-accounts/tokens/ERC4626.sol, MIT, Vectorized/solady
///         v0.1.22, commit 65e87c72a5ee4a6708946b25611ec5f980ceba70; byte-identical). ERC-4626
///         shares are themselves an ERC-20, so the vault's share-allowance accounting is Solady's
///         unmodified code. This subclass adds ONLY the three required overrides (asset/name/
///         symbol); it changes none of the defensive logic. Distinct from the existing
///         oz-erc4626-safe (OpenZeppelin) - a different, independent codebase the wal detectors
///         were never tuned against. Built/run only in Docker.
contract SoladyVaultFixture is ERC4626 {
    address internal immutable _assetToken;

    constructor(address assetToken_) {
        _assetToken = assetToken_;
    }

    function asset() public view override returns (address) {
        return _assetToken;
    }

    function name() public pure override returns (string memory) {
        return "Solady Vault Shares (holdout)";
    }

    function symbol() public pure override returns (string memory) {
        return "SVS";
    }
}
