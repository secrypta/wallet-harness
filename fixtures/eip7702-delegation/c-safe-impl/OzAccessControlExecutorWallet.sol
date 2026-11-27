// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "../../vendor/oz/access/AccessControl.sol";

/// @title OzAccessControlExecutorWallet - a delegate executor whose arbitrary-call execution is
///        gated by the UNMODIFIED OpenZeppelin `AccessControl`. Real-safe (tier c) vehicle for
///        the eip7702-delegation vector, using a DIFFERENT real authorization library than the
///        Solady-Ownable ERC7821 fixture (role-based access control vs single-owner).
/// @notice The eip7702 danger is a delegate executor that lets an UNAUTHORIZED party run
///         arbitrary calls (and sweep the account). Here the authorization is unmodified OZ
///         v5.1.0 `AccessControl` (`onlyRole` / `hasRole`, reverting
///         `AccessControlUnauthorizedAccount`), vendored byte-identical under fixtures/vendor/oz/
///         (see fixtures/vendor/PROVENANCE.md). The only authored code is the thin `execute`
///         wrapper gated behind `onlyRole(EXECUTOR_ROLE)`. A caller without the role (a malicious
///         7702 delegate / arbitrary account) reverts and cannot drain, so the harness must stay
///         silent (BLOCKED).
contract OzAccessControlExecutorWallet is AccessControl {
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    constructor(address executor_) {
        _grantRole(EXECUTOR_ROLE, executor_);
    }

    receive() external payable {}

    /// @notice Execute an arbitrary call, only for holders of EXECUTOR_ROLE (enforced by the
    ///         unmodified OZ AccessControl `onlyRole`).
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyRole(EXECUTOR_ROLE)
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "executor: call failed");
        return ret;
    }
}
