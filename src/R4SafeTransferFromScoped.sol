// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// R4 real-form SAFE control (0-FP): same permit + SafeERC20 static safeTransferFrom form, but
// the pull is bounded to exactly the action amount (not a balanceOf sweep, not max). R4 must
// stay SILENT. Target src: src/R4SafeTransferFromScoped.sol.

interface IERC20Permit {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransferFrom(IERC20Permit token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "transferFrom failed");
    }
}

contract R4SafeTransferFromScoped {
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
        IERC20Permit(token).permit(owner, address(this), value, deadline, v, r, s);
        // Scoped: pull exactly the action amount via the SafeERC20 static form -> no over-pull.
        SafeERC20.safeTransferFrom(IERC20Permit(token), owner, to, actionAmount);
    }
}
