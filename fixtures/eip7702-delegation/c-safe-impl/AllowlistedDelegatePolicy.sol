// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AllowlistedDelegatePolicy - reference implementation of the canonical EIP-7702 defense.
/// @notice EIP-7702 is a brand-new primitive (live since Pectra, 2025) with no single canonical
///         audited third-party library yet, so tier (c) for this vector is a faithful
///         REFERENCE-IMPL of the defense every 7702-aware wallet should apply - honestly marked
///         as such (not vendored code). See PROVENANCE.md.
///
///         The policy: honor a 7702 delegation ONLY when the named delegate is on a curated
///         allow-list of audited contracts, and refuse everything else. The attacker's reusable
///         sweeper is never allow-listed, so the delegation that would run hostile code in the
///         account's context is rejected before any code executes -> the drain path is
///         unreachable (BLOCKED). A guard (see test) installs an allow-listed delegate to show
///         the policy is not vacuously rejecting everything.
contract AllowlistedDelegatePolicy {
    address public immutable owner;
    mapping(address => bool) public audited;
    address public activeDelegate;

    event DelegationRejected(address indexed delegate);
    event DelegationInstalled(address indexed delegate);

    error DelegateNotAllowlisted(address delegate);

    constructor() {
        owner = msg.sender;
    }

    function setAudited(address delegate_, bool ok) external {
        require(msg.sender == owner, "only owner");
        audited[delegate_] = ok;
    }

    /// Honor a 7702 delegation only if the named delegate is audited/allow-listed.
    function honorDelegation(address delegate_) external {
        if (!audited[delegate_]) {
            emit DelegationRejected(delegate_);
            revert DelegateNotAllowlisted(delegate_);
        }
        activeDelegate = delegate_;
        emit DelegationInstalled(delegate_);
    }

    function activate(bytes calldata data) external returns (bytes memory) {
        require(activeDelegate != address(0), "no delegation");
        (bool ok, bytes memory ret) = activeDelegate.delegatecall(data);
        require(ok, "delegate execution failed");
        return ret;
    }

    receive() external payable {}
}

/// @dev A minimal audited delegate for the guard test: shows an allow-listed delegate installs
///      and runs, so the BLOCKED verdict means "unknown delegate rejected", not "nothing works".
contract AuditedNoopDelegate {
    event Ran();
    function run() external {
        emit Ran();
    }
}
