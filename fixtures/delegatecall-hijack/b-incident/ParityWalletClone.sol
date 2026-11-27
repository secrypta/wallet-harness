// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ParityWalletClone - minimized offline clone of the delegatecall-hijack drain of the
///        Parity multisig wallet (first Parity hack, 2017-07-19).
/// @notice NOT our toy: a faithful, minimized reproduction of the affected wallet's exploited
///         surface. Each Parity multisig was a thin proxy that `delegatecall`ed a single shared
///         WalletLibrary. The library's `initWallet` (ownership setup) was NOT guarded against a
///         second call and was reachable through the proxy's delegatecall fallback, so anyone
///         could re-initialize a live wallet's owner to themselves and then `execute` a transfer
///         of its entire balance. Root cause: a delegatecall to a library whose state-changing
///         initializer had no "already initialized" guard. Only that surface is modeled here.
///         Provenance (tx hashes, addresses, source) in parity-wallet-library-victim/PROVENANCE.md.
///         Offline only - no network, no live RPC. Build/run in Docker.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.

/// @dev The shared library. Runs in the PROXY's storage context via delegatecall. `owner` here
///      aligns with the proxy's slot 0.
contract ParityWalletLibrary {
    address public owner;

    /// @notice THE BUG: no "already initialized" guard, so this ownership setup can be called
    ///         again on a live, funded wallet - by anyone - through the proxy's delegatecall.
    function initWallet(address newOwner) public {
        owner = newOwner;
    }

    function execute(address to, uint256 value) public {
        require(msg.sender == owner, "Parity: not owner");
        (bool ok,) = to.call{value: value}("");
        require(ok, "Parity: send failed");
    }
}

/// @dev The per-user wallet proxy. Holds the ETH; forwards unknown calls to the library via
///      delegatecall, so library code mutates THIS contract's storage. `owner` is slot 0, aligned
///      with the library's `owner`.
contract ParityWalletProxy {
    address public owner;
    address public immutable lib;

    constructor(address lib_, address initialOwner) {
        lib = lib_;
        owner = initialOwner;
    }

    receive() external payable {}

    fallback() external payable {
        address target = lib;
        (bool ok,) = target.delegatecall(msg.data);
        require(ok, "Parity: delegatecall failed");
    }
}
