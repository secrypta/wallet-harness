// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPermitToken {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @title Challenge - minimized AnyswapV4Router with the real permit-validation bypass.
/// @notice This is the VULNERABLE version, reproducing the incident. Your job is to fix
///         `anySwapOutUnderlyingWithPermit` so the permit-bypass drain no longer works, WITHOUT
///         breaking a genuine with-permit swap.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and arguments. You may change only the body.
///
/// THE BUG (as documented): the router forwards `permit(...)` to the token and only requires
/// that the call did not revert. A token without `permit` (WETH) hits its permissive fallback
/// and succeeds without granting anything; the router then `transferFrom`s `amount` using the
/// owner's PRE-EXISTING standing approval - so anyone can drain any address that approved it.
contract Challenge {
    function anySwapOutUnderlyingWithPermit(
        address owner,
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // BUG: trusts that the permit succeeded merely because it did not revert.
        IPermitToken(token).permit(owner, address(this), amount, deadline, v, r, s);
        IPermitToken(token).transferFrom(owner, msg.sender, amount);
    }
}
