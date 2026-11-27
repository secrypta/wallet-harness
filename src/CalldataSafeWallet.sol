// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20View {
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @title CalldataSafeWallet - wallet with the DEFENSIVE execution policy.
/// @notice It simulates the real effect of the calldata instead of trusting the label.
///         It snapshots its asset balance and its allowance to the counterparty, runs the
///         module's `connect()`, then asserts the net effect matches a benign action: no
///         new allowance to the counterparty and no balance change. A hidden
///         `approve`/`transfer` makes the assertion fail, reverting the whole call (and
///         rolling back the hidden effect) - so the drain never takes hold. A genuinely
///         benign module changes nothing and passes.
contract CalldataSafeWallet {
    error HiddenAllowanceGrant();
    error HiddenBalanceChange();

    function executeSimulated(address module, address asset) external {
        uint256 allowanceBefore = IERC20View(asset).allowance(address(this), module);
        uint256 balanceBefore = IERC20View(asset).balanceOf(address(this));

        (bool ok, ) = module.delegatecall(abi.encodeWithSignature("connect()"));
        require(ok, "module call failed");

        // Decode-by-effect: a benign "connect" must not grant the counterparty an
        // allowance over, or move, this wallet's assets. If it did, the presented intent
        // does not match the real effect - reject (revert rolls back the hidden grant).
        if (IERC20View(asset).allowance(address(this), module) != allowanceBefore) {
            revert HiddenAllowanceGrant();
        }
        if (IERC20View(asset).balanceOf(address(this)) != balanceBefore) {
            revert HiddenBalanceChange();
        }
    }
}
