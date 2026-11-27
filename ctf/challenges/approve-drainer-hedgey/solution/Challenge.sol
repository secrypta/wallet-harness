// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the Hedgey stale-approval drain.
/// @notice The only change is in `cancelCampaign`: revoke the approval granted to the campaign's
///         locker at create-time (set it back to zero). The refund still happens, but the
///         residual allowance no longer survives the cancel, so it cannot drain the pool.
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

    function createLockedCampaign(bytes16 id, uint256 amount, address locker) external {
        token.transferFrom(msg.sender, address(this), amount);
        campaigns[id] = Campaign({creator: msg.sender, amount: amount, locker: locker, active: true});
        token.approve(locker, amount);
    }

    function cancelCampaign(bytes16 id) external {
        Campaign storage c = campaigns[id];
        require(c.active && c.creator == msg.sender, "not creator / inactive");
        c.active = false;
        token.transfer(c.creator, c.amount);
        // FIX: revoke the standing approval so it cannot drain the pooled balance after cancel.
        token.approve(c.locker, 0);
    }
}
