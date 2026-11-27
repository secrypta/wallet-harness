// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Challenge - minimized Hedgey ClaimCampaigns with the real stale-approval bug.
/// @notice This is the VULNERABLE version. Your job is to fix `cancelCampaign` so the
///         stale-approval drain no longer works, WITHOUT breaking the refund.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and argument. You may change only the body of `cancelCampaign`.
///
/// Campaigns deposit tokens into the shared contract balance. On create the contract approves a
/// campaign-supplied `locker` (unvalidated) so it can move claimed tokens. On cancel the deposit
/// is refunded - but the approval to `locker` is NOT cleared, so it stands against the contract's
/// whole pooled balance. That residual allowance is the drain.
contract Challenge {
    IERC20Min public immutable token;

    struct Campaign {
        address creator;
        uint256 amount;
        address locker;
        bool active;
    }

    mapping(bytes16 => Campaign) public campaigns;

    constructor(address _token) {
        token = IERC20Min(_token);
    }

    /// @notice Create a campaign. `locker` is recorded and approved to move up to `amount`.
    function createLockedCampaign(bytes16 id, uint256 amount, address locker) external {
        token.transferFrom(msg.sender, address(this), amount);
        campaigns[id] = Campaign({creator: msg.sender, amount: amount, locker: locker, active: true});
        token.approve(locker, amount);
    }

    /// @notice Cancel a campaign: refund the campaign's own deposit to its creator.
    function cancelCampaign(bytes16 id) external {
        Campaign storage c = campaigns[id];
        require(c.active && c.creator == msg.sender, "not creator / inactive");
        c.active = false;
        token.transfer(c.creator, c.amount);
        // BUG: the approval granted to c.locker at create-time is NEVER revoked here.
    }
}
