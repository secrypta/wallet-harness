// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - the ERC-2771 trusted forwarder (VULNERABLE version).
/// @notice Modeled on the Magic Eden / Limit Break Payment Processor V2 drain (2026-09-24,
///         ~$2.8M; example tx 0x9050e2...93d3). The payment processor trusts whatever sender
///         this forwarder appends to the calldata. The bug: `forward` lets ANY caller claim
///         ANY `from`, so an attacker relays a trade "as the victim" and the processor settles
///         it against the victim's NFTs (pulled with the victim's lingering operator approval).
///
///         Your job is to fix `forward` so a caller can only relay their OWN meta-transaction,
///         WITHOUT breaking the legitimate relay. Keep the signature exactly as-is; change only
///         the body.
contract Challenge {
    function forward(address target, bytes calldata data, address from)
        external
        returns (bool ok, bytes memory ret)
    {
        // BUG: the caller is never proven to be `from`, yet the target trusts the appended
        //      `from` as the acting party. Anyone can relay as anyone.
        (ok, ret) = target.call(abi.encodePacked(data, from));
        require(ok, "forward: target call failed");
    }
}
