// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title Challenge - reference FIX for the Nomad Bridge re-init drain.
/// @notice A never-proven (forged) message resolves to the zero root, and the upgrade left the
///         zero root "acceptable". The fix rejects the zero root at the point funds leave, so a
///         forged message can no longer drain the bridge, while a legitimately proven non-zero
///         root still processes.
contract Challenge {
    mapping(bytes32 => uint256) public confirmAt;
    bool public initialized;
    address public immutable token;
    address public immutable owner;

    constructor(address token_) {
        token = token_;
        owner = msg.sender;
    }

    function initialize() external {
        require(!initialized, "already initialized");
        initialized = true;
        confirmAt[bytes32(0)] = block.timestamp;
    }

    function confirmRoot(bytes32 root) external {
        require(msg.sender == owner, "not owner");
        require(root != bytes32(0), "zero root");
        confirmAt[root] = block.timestamp;
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        uint256 t = confirmAt[root];
        return t != 0 && t <= block.timestamp;
    }

    function process(bytes32 provenRoot, address to, uint256 amount) external {
        // FIX: a real proof never resolves to the zero root; reject the forged/un-proven case.
        require(provenRoot != bytes32(0), "forged: zero root not provable");
        require(acceptableRoot(provenRoot), "!proven root");
        IERC20Min(token).transfer(to, amount);
    }
}
