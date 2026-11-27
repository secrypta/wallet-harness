// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title approve-drainer (b) HOLDOUT fixture - Pennysia Settlement stale-approval drain (2026-11-12).
/// @notice Minimized, fully OFFLINE replay of the documented Pennysia drain. `PennysiaSettlement`
///         exposed an `executeSwap` that takes a "route" = a venue address + raw calldata and
///         executes it from the Settlement's own context. Because users granted the Settlement a
///         (stale) token approval, an attacker crafted a route whose venue was the token and whose
///         calldata was `transferFrom(victim, Settlement, amount)` - the Settlement is the approved
///         spender, so the victim's standing allowance is spent. This is the arbitrary-callee /
///         stale-approval class (relates to R11).
///
///         Facts verified by M against the public write-ups (dev.to/pandasecurity + SlowMist alert;
///         see PROVENANCE.md) and used as labels only, never as a detection signal. Victim
///         addresses are truncated in the sources, so the victim here is an EXPLICIT STAND-IN.
///         HOLDOUT: authored after wal froze at v0.1 (label=vuln -> expect VULNERABLE).
///         Self-contained; no third-party source copied.

/// @dev Minimal USDC-like ERC-20 (6 decimals; test vehicle only).
contract MiniUSDC {
    uint8 public constant decimals = 6;
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

/// @dev Minimized PennysiaSettlement: THE BUG is `executeSwap`, which forwards an attacker-chosen
///      `(venue, calldata)` route as a low-level call from the Settlement's own context with no
///      allow-listing of the venue or the call. Since victims approved the Settlement, a crafted
///      `transferFrom` route spends their standing approval.
contract PennysiaSettlementClone {
    function executeSwap(address venue, bytes calldata route) external {
        (bool ok, ) = venue.call(route);
        require(ok, "swap failed");
    }
}
