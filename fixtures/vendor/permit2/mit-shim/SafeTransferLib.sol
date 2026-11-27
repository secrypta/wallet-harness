// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {ERC20} from "./ERC20.sol";

/// @title SafeTransferLib - minimal MIT token-transfer helper (Permit2 vendoring shim).
/// @notice Exposes the exact `safeTransferFrom(ERC20, address, address, uint256)` API the
///         real Uniswap Permit2 uses (`using SafeTransferLib for ERC20`). Replaces solmate's
///         AGPL-3.0 `SafeTransferLib` so the Permit2 vendoring stays pure MIT (Variant C);
///         Permit2's core is otherwise unmodified. Does a low-level `transferFrom` and
///         requires success plus (no return data, or a `true` return) - the standard
///         non-standard-ERC20-tolerant safe-transfer check.
library SafeTransferLib {
    error TransferFromFailed();

    function safeTransferFrom(ERC20 token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(ERC20.transferFrom.selector, from, to, amount)
        );
        if (!success || !(data.length == 0 || abi.decode(data, (bool)))) {
            revert TransferFromFailed();
        }
    }
}
