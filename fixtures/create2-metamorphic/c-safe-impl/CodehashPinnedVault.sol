// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ICodeId {
    function codeId() external view returns (bytes32);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title CodehashPinnedVault - reference implementation of the codehash-pinning defense.
/// @notice No single canonical third-party library covers "don't trust a metamorphic approved
///         address", so tier (c) is a faithful REFERENCE-IMPL of the canonical defense, honestly
///         marked as such (not vendored). See PROVENANCE.md.
///
///         The vault never hands a mutable-code address a raw standing ERC-20 allowance. It
///         records the spender's effective code identity (EXTCODEHASH stand-in via codeId()) at
///         trust time and re-verifies it on every outflow. If the code at the approved address
///         changes (a metamorphic swap), the pinned identity no longer matches and the drain
///         path reverts (BLOCKED). A guard shows an unchanged spender can still settle, so the
///         defense is not vacuous.
contract CodehashPinnedVault {
    address public immutable owner;
    mapping(address => bytes32) public pinnedCodeId; // spender => code identity at trust time

    event SpenderTrusted(address indexed spender, bytes32 codeId);
    event SpenderRevoked(address indexed spender, bytes32 wasCodeId, bytes32 nowCodeId);

    error CodeIdChanged(address spender, bytes32 pinned, bytes32 current);
    error UntrustedSpender(address spender);

    constructor() {
        owner = msg.sender;
    }

    /// Trust a spender while it carries known-good code: pin its effective code identity.
    function trust(address spender) external {
        require(msg.sender == owner, "only owner");
        bytes32 id = ICodeId(spender).codeId();
        require(id != bytes32(0), "spender has no code");
        pinnedCodeId[spender] = id;
        emit SpenderTrusted(spender, id);
    }

    /// Guarded settlement: re-verify the spender's code identity before any funds move. On a
    /// mismatch the vault revokes the pin and refuses - a metamorphic swap cannot drain.
    function settle(address token, address spender, address to, uint256 amount) external {
        bytes32 pinned = pinnedCodeId[spender];
        if (pinned == bytes32(0)) revert UntrustedSpender(spender);
        bytes32 current = ICodeId(spender).codeId();
        if (current != pinned) {
            pinnedCodeId[spender] = bytes32(0);
            emit SpenderRevoked(spender, pinned, current);
            revert CodeIdChanged(spender, pinned, current);
        }
        IERC20(token).transfer(to, amount);
    }
}
