// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CalldataVulnerableWallet - wallet with the UNSAFE execution policy.
/// @notice It executes a module "by its label": it trusts the presented action name and
///         delegatecalls the module's `connect()` without inspecting the real effect. A
///         module whose `connect()` hides an `approve`/`transfer` therefore drains the
///         wallet - the label is cosmetic, the calldata is the truth.
contract CalldataVulnerableWallet {
    /// @param label the presented, human-facing action (e.g. "Connect") - trusted blindly.
    /// @param module the contract whose `connect()` is delegatecalled in this wallet's
    ///        context (so its hidden effect acts on this wallet's assets).
    function executeByLabel(string calldata label, address module) external {
        label; // the UI label is all this unsafe wallet checks - i.e. nothing real
        (bool ok, ) = module.delegatecall(abi.encodeWithSignature("connect()"));
        require(ok, "module call failed");
    }
}
