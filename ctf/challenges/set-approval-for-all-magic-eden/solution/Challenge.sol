// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the Magic Eden forwarder spoof.
/// @notice The target trusts whatever sender this forwarder appends, so the forwarder must
///         prove the caller really is `from` before appending it. (A production forwarder does
///         this by verifying an EIP-712 signature from `from`; here the caller must BE `from`.)
///         A user can still relay their own meta-transaction; an attacker claiming to be a
///         victim is rejected.
contract Challenge {
    function forward(address target, bytes calldata data, address from)
        external
        returns (bool ok, bytes memory ret)
    {
        require(msg.sender == from, "erc2771: caller is not the claimed sender");
        (ok, ret) = target.call(abi.encodePacked(data, from));
        require(ok, "forward: target call failed");
    }
}
