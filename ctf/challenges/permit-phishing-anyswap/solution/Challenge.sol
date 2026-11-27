// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IPermitToken {
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @title Challenge - reference FIX for the Anyswap permit-bypass drain.
/// @notice Don't trust that `permit` "did not revert". Verify it actually granted the allowance
///         this call needs: a genuine permit leaves `allowance(owner, router) == amount`, while
///         a no-op fallback (WETH) leaves only the owner's pre-existing standing approval, which
///         will not equal `amount`. That mismatch is rejected, so the standing-approval drain is
///         blocked while a real with-permit swap still goes through.
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
        IPermitToken(token).permit(owner, address(this), amount, deadline, v, r, s);
        // FIX: require the permit actually granted exactly this call's allowance.
        require(
            IPermitToken(token).allowance(owner, address(this)) == amount,
            "router: permit did not grant the expected allowance"
        );
        IPermitToken(token).transferFrom(owner, msg.sender, amount);
    }
}
