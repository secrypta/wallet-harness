// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// permit-phishing consumer target for rule R4 (safe side): a permit CONSUMER bounded to the
// action amount. Pulls exactly what the action needs and leaves the rest of the balance, so
// an over-signed permit (or a surplus balance) cannot be swept.

interface IERC20PermitConsume {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

/// @title ScopedPermitRouter - DEFENSIVE permit consumer (R4, safe).
/// @notice Requests a permit for exactly `actionAmount` and pulls exactly `actionAmount`; it
///         never transfers more than the action needs, so a surplus balance (or a permit
///         value larger than the action) is left untouched. The permit is consumed bounded
///         to the action.
contract ScopedPermitRouter {
    function relay(
        address token,
        address owner,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address to,
        uint256 actionAmount
    ) external {
        IERC20PermitConsume(token).permit(owner, address(this), actionAmount, deadline, v, r, s);
        // Pull exactly what the action needs; the rest of the balance stays with the owner.
        IERC20PermitConsume(token).transferFrom(owner, to, actionAmount);
    }
}
