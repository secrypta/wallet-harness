// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title malicious-calldata (b) HOLDOUT fixture - SquidMulticall approval exploit (2026-04-07).
/// @notice Minimized, fully OFFLINE, CLASS-LEVEL model of the documented SquidMulticall drain:
///         the Squid `SquidMulticall` helper exposed a PERMISSIONLESS `run(Call[])` that executes
///         an attacker-supplied list of arbitrary external calls from the helper's own context.
///         Victims who had granted the helper a token approval were drained when a bot called
///         `run` with a `transferFrom(victim, attacker, amount)` call - the helper is the approved
///         spender, so the standing allowance is spent. ~$517K was taken across five chains; the
///         Decurity timeline describes the BSC leg as one crafted `Call` moving 1 WETH.
///
///         CLASS-LEVEL: the specific on-chain tx hash and the real attacker/victim/helper
///         addresses are NOT reproduced - they could not be authoritatively confirmed, so
///         (as in the CrimeEnjoyor / Inferno fixtures) attacker and victim are EXPLICIT
///         PLACEHOLDERS and no invented identifier is asserted. The reproduced mechanism is the
///         documented one (permissionless arbitrary-call forwarder spends a standing approval).
///         See PROVENANCE.md for the authoritative write-ups.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was NOT tuned to pass it
///         (label=vuln -> expect VULNERABLE). Self-contained; no third-party source copied.

/// @dev Minimal self-contained ERC-20 (test vehicle only; never deploy on a real net).
contract MiniToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(balanceOf[from] >= amt, "insufficient");
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @dev One attacker-supplied call in the multicall batch.
struct Call {
    address target;
    bytes callData;
}

/// @dev The vulnerable helper: `run` is permissionless and forwards arbitrary calls from the
///      helper's own context (so the helper is msg.sender of each forwarded call). A victim who
///      approved this helper can be drained by anyone who crafts a transferFrom call.
contract SquidMulticallClone {
    function run(Call[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = calls[i].target.call(calls[i].callData);
            require(ok, "call failed");
        }
    }
}
