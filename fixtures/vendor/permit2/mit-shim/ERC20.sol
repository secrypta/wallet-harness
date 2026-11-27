// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title ERC20 - minimal MIT token handle (Permit2 vendoring shim, Variant C).
/// @notice The real Uniswap Permit2 imports solmate's `ERC20` purely as the typed token
///         address handed to `SafeTransferLib.safeTransferFrom`; its core never calls an
///         ERC20 method directly. solmate is AGPL-3.0-only, so to keep this repo pure MIT we
///         vendor Permit2 byte-for-byte EXCEPT its two solmate imports, which point here
///         instead. This declares exactly the surface Permit2's core needs: the `ERC20`
///         type (so `ERC20(tokenAddress)` casts and `using SafeTransferLib for ERC20` work).
///         Permit2's defensive logic (allowance accounting, signature verification, nonce/
///         expiration) is untouched.
abstract contract ERC20 {
    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool);
    function transfer(address to, uint256 amount) public virtual returns (bool);
    function approve(address spender, uint256 amount) public virtual returns (bool);
    function balanceOf(address owner) public view virtual returns (uint256);
    function allowance(address owner, address spender) public view virtual returns (uint256);
}
