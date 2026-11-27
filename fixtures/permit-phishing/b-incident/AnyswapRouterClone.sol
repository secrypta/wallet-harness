// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title permit-phishing (b) HOLDOUT fixture - Anyswap/Multichain V4Router permit-bypass (2022-01-19).
/// @notice Minimized, fully OFFLINE replay of the documented AnyswapV4Router drain. The router's
///         `anySwapOutUnderlyingWithPermit` forwards a `permit(...)` to the underlying token and
///         only requires that the call did NOT revert - it never checks that an allowance was
///         actually granted by a valid signature. WETH has no `permit`, so the call hits WETH's
///         permissive fallback and succeeds without verifying any signature; the router then
///         `transferFrom`s the underlying using the victim's PRE-EXISTING approval to the router.
///         Anyone can thus drain any address that had approved the router.
///
///         Real on-chain facts (verified against coinspect learn-evm-attacks / BlockSec / Zengo -
///         see PROVENANCE.md) are used as labels only, never as a detection signal. The victim
///         address is a coinspect PoC constant (NOT confirmed on-chain) and is an explicit
///         stand-in. HOLDOUT: authored after wal froze at v0.1 (label=vuln -> expect VULNERABLE).
///         Self-contained; no third-party source copied.

/// @dev WETH-like ERC-20 with NO `permit` and a permissive fallback (as WETH9 has): a call to a
///      non-existent `permit(...)` selector falls through to the fallback and returns success.
contract WethNoPermit {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
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

    // WETH9 exposes no permit(); a permit(...) call lands here and does NOT revert.
    fallback() external payable {}
    receive() external payable {}
}

interface IERC2612Permit {
    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external;
}

/// @dev Minimized AnyswapV4Router: the exploited `anySwapOutUnderlyingWithPermit`. THE BUG: it
///      forwards permit() to the underlying and only cares that the call didn't revert, then
///      transferFroms the underlying - spending the victim's standing approval to the router.
contract AnyswapV4RouterClone {
    function anySwapOutUnderlyingWithPermit(
        address from,
        address underlying,
        uint256 amount,
        address to,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Forwarded permit: only "did not revert" is checked (WETH's fallback accepts it, so no
        // signature is ever verified). The result is ignored.
        try IERC2612Permit(underlying).permit(from, address(this), amount, deadline, v, r, s) {} catch {}
        // Drain via the victim's PRE-EXISTING approval to this router.
        WethNoPermit(payable(underlying)).transferFrom(from, to, amount);
    }
}
