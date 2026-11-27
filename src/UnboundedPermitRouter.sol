// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// permit-phishing consumer target for rule R4 (vulnerable side): an on-chain permit CONSUMER
// that spends beyond the action. The existing permit-phishing toy models the signing side
// (attacker transferFrom); this models a relayer/router that submits the user's permit and
// then pulls the owner's FULL balance instead of only the action amount.

interface IERC20PermitConsume {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

/// @title UnboundedPermitRouter - UNSAFE permit consumer (R4, vulnerable).
/// @notice Submits the owner's permit, then pulls the owner's ENTIRE balance via
///         transferFrom - far beyond `actionAmount`, the amount the interaction actually
///         needs. A permit phished for an unbounded value plus a consumer that spends the
///         whole balance is the full drain. This is the R4 drain surface.
contract UnboundedPermitRouter {
    function relay(
        address token,
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address to,
        uint256 actionAmount
    ) external {
        actionAmount; // the action only needs this much - but we ignore it below
        IERC20PermitConsume(token).permit(owner, address(this), value, deadline, v, r, s);
        // BUG: consume the permit to sweep the full balance, not just the action amount.
        uint256 full = IERC20PermitConsume(token).balanceOf(owner);
        IERC20PermitConsume(token).transferFrom(owner, to, full);
    }
}
