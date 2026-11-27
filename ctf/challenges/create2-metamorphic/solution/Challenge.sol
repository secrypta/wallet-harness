// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title Challenge - reference FIX for the create2-metamorphic vector.
/// @notice Trust the CODE, not the address. `authorize` pins the trustee's codehash
///         (EXTCODEHASH) at the moment it is vetted; `pull` re-checks that the code at the
///         trusted address is still exactly that pinned code. If the code was swapped
///         (metamorphic / look-alike redeploy), the codehash no longer matches and the pull
///         is rejected. A genuinely unchanged trustee still works.
contract Challenge {
    address public immutable token;

    address public trustee;
    bytes32 public pinnedCodehash;

    constructor(address token_) {
        token = token_;
    }

    function authorize(address trustee_) external {
        // FIX: pin the exact code that is being vetted, not just the address.
        trustee = trustee_;
        pinnedCodehash = trustee_.codehash;
    }

    function pull(address to, uint256 amount) external {
        require(msg.sender == trustee, "pull: caller is not the trustee");
        // FIX: the code at the trusted address must still be the vetted code.
        require(msg.sender.codehash == pinnedCodehash, "pull: trustee code changed");
        IERC20Min(token).transfer(to, amount);
    }
}
