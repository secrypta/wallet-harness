// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title Challenge - minimized Nomad Replica whose upgrade re-init trusts the zero root.
/// @notice This is the VULNERABLE version. Your job is to fix `process` so the forged-message
///         drain (Nomad Bridge, 2022-08-01) can no longer happen, WITHOUT breaking legitimate
///         bridging.
///
///         Keep the `process` signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only its body. `initialize` models the incident's
///         buggy upgrade (it re-ran and marked the zero root acceptable) - leave it as-is.
///
///         The bug: because `initialize()` left the ZERO root acceptable, a message that was
///         never actually proven (its root resolves to bytes32(0)) passes the root check in
///         `process`, so an attacker drains custodied funds with a fabricated message.
contract Challenge {
    mapping(bytes32 => uint256) public confirmAt; // root => time it became acceptable (0 = never)
    bool public initialized;
    address public immutable token;
    address public immutable owner;

    constructor(address token_) {
        token = token_;
        owner = msg.sender;
    }

    /// @notice The re-initialization the upgrade triggered (models the incident). THE DEFECT:
    ///         it marks the zero root acceptable, disabling message authentication. Leave as-is.
    function initialize() external {
        require(!initialized, "already initialized");
        initialized = true;
        confirmAt[bytes32(0)] = block.timestamp; // zero root acceptable -> auth disabled
    }

    /// @notice Governance marks a genuinely proven (non-zero) root acceptable. Not part of the
    ///         puzzle - this is the legitimate path.
    function confirmRoot(bytes32 root) external {
        require(msg.sender == owner, "not owner");
        require(root != bytes32(0), "zero root");
        confirmAt[root] = block.timestamp;
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        uint256 t = confirmAt[root];
        return t != 0 && t <= block.timestamp;
    }

    /// @notice Release custodied funds for a message whose root is acceptable. `provenRoot` is
    ///         the root the message's proof resolves to (bytes32(0) for an un-proven/forged msg).
    function process(bytes32 provenRoot, address to, uint256 amount) external {
        // BUG: honors any "acceptable" root - including the zero root the upgrade left open.
        require(acceptableRoot(provenRoot), "!proven root");
        IERC20Min(token).transfer(to, amount);
    }
}
