// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Custody {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title GuardedCustodyApproveWallet - DEFENSIVE pooled-custody approval policy (R13 toy safe).
/// @notice Identical pooled custody to the vulnerable version (it pulls deposits into its own
///         balance), but a caller-supplied `spender` must be a member of an owner-curated
///         address allow-list BEFORE any approval is granted. The membership check + revert
///         means an attacker-chosen spender can never receive an allowance over the pool, so
///         the residual-allowance drain is impossible and R13 must stay silent.
/// @dev    Proves the detector keys on (custody + UNVALIDATED spender), not on custody alone:
///         custody is present here too, yet the allow-list gate flips the verdict to safe.
///         Toy; never deploy.
contract GuardedCustodyApproveWallet {
    IERC20Custody public immutable token;
    address public immutable owner;
    mapping(address => bool) public allowedSpenders;

    error SpenderNotAllowed();

    constructor(IERC20Custody token_) {
        token = token_;
        owner = msg.sender;
    }

    /// @notice Owner curates which spenders may ever receive an allowance over the pool.
    function setAllowed(address spender, bool ok) external {
        require(msg.sender == owner, "not owner");
        allowedSpenders[spender] = ok;
    }

    function createCampaign(uint256 amount, address spender) external {
        // Reject any spender that is not on the owner-curated allow-list.
        if (!allowedSpenders[spender]) revert SpenderNotAllowed();
        token.transferFrom(msg.sender, address(this), amount);
        token.approve(spender, amount);
    }
}
