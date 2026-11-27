// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Settle {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title ReplaySettlement - UNSAFE signature verifier (R5, vulnerable).
/// @notice Authorizes moving the owner's assets from a signature over a BARE message hash:
///         no EIP-712 domain separator, no nonce, no deadline. Because nothing binds the
///         signature to a single use, a single contract or a point in time, a relayer can
///         REPLAY one signed order again and again until the owner is drained (and the same
///         signature would also be valid on a clone contract / another chain). This is the
///         signature-missing-deadline/nonce/domain surface that rule R5 flags.
contract ReplaySettlement {
    event Settled(address indexed owner, address indexed recipient, uint256 amount);

    /// @dev Bare hash: deliberately omits the "\x19\x01" + domainSeparator prefix, the
    ///      owner nonce and any deadline.
    function hashOrder(address owner, address token, uint256 amount, address recipient)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(owner, token, amount, recipient));
    }

    function settle(address owner, address token, uint256 amount, address recipient, uint8 v, bytes32 r, bytes32 s)
        external
    {
        address recovered = ecrecover(hashOrder(owner, token, amount, recipient), v, r, s);
        require(recovered != address(0) && recovered == owner, "ReplaySettlement: bad signature");
        // No nonce consumed, no deadline checked -> the same signature settles forever.
        IERC20Settle(token).transferFrom(owner, recipient, amount);
        emit Settled(owner, recipient, amount);
    }
}
