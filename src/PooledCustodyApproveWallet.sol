// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Custody {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title PooledCustodyApproveWallet - UNSAFE pooled-custody approval policy (R13 toy vuln).
/// @notice Deposits from many callers are pooled into THIS contract's own balance. When a
///         campaign is created the contract approves a CALLER-SUPPLIED `spender` over that
///         shared pool with NO validation: no allow-list membership check, not bound to
///         msg.sender, not a fixed audited counterparty. The residual, unrevoked allowance
///         lets that spender `transferFrom` the whole pooled balance - the code-level shape
///         of the Hedgey Finance drain.
/// @dev    The approved amount is BOUNDED (not type(uint256).max), so this is a DISTINCT
///         surface from R1 (unbounded-approve): the defect is (pooled custody +
///         attacker-supplied spender + no gate), independent of the amount. Toy; never deploy.
contract PooledCustodyApproveWallet {
    IERC20Custody public immutable token;

    constructor(IERC20Custody token_) {
        token = token_;
    }

    /// @param spender comes straight from the caller with NO validation, and is approved to
    ///        move `amount` out of this contract's pooled balance.
    function createCampaign(uint256 amount, address spender) external {
        // Pull the caller's deposit into the shared contract balance (pooled custody).
        token.transferFrom(msg.sender, address(this), amount);
        // Grant a bounded approval to the unvalidated, caller-supplied spender.
        token.approve(spender, amount);
    }
}
