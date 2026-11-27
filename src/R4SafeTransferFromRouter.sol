// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// R4 real-form VULN toy: a permit consumer whose pull sink is the SafeERC20 static library
// form `SafeERC20.safeTransferFrom(token, owner, to, full)` (the shape real routers use, e.g.
// Anyswap TransferHelper.safeTransferFrom), not the member `token.transferFrom`. Consumes the
// permit, then sweeps the owner's FULL balance -> beyond the action amount. R4 must FIRE once
// the sink is recognized across member + static forms. Target src: src/R4SafeTransferFromRouter.sol.

interface IERC20Permit {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

library SafeERC20 {
    // static form: SafeERC20.safeTransferFrom(token, from, to, value) -> from = args[1], amount = last
    function safeTransferFrom(IERC20Permit token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "transferFrom failed");
    }
}

contract R4SafeTransferFromRouter {
    using SafeERC20 for IERC20Permit;

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
        actionAmount; // the action only needs this much - ignored below
        IERC20Permit(token).permit(owner, address(this), value, deadline, v, r, s);
        // BUG: sweep the full balance via the SafeERC20 static form, not just the action amount.
        uint256 full = IERC20Permit(token).balanceOf(owner);
        SafeERC20.safeTransferFrom(IERC20Permit(token), owner, to, full);
    }
}
