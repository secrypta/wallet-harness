// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./furucombo-proxy-victim/PROVENANCE.md for the full block)
//   Vector:  delegatecall-hijack   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Furucombo "evil contract" drain, 2021-02-27, Ethereum, ~$15M across 21
//            assets / 22 users. Furucombo's proxy executed user-chosen, whitelisted
//            "handlers" by DELEGATECALL (combo execution). A whitelisted handler - the
//            Aave V2 lending-pool proxy - had an uninitialized implementation; the
//            attacker called initialize() to point it at their own contract, then had
//            the Furucombo proxy delegatecall it. Attacker code ran in the Furucombo
//            proxy's storage/auth context and spent users' standing approvals to the
//            proxy (transferFrom) - "cascading trust".
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction of the trust cascade
//            (whitelisted-handler delegatecall + unguarded initializer on the trusted
//            handler), NOT a byte replay of the real two-hop proxy resolution. The exact
//            storage-slot mechanics of the live Aave proxy are abstracted; the vector a
//            delegatecall-hijack detector reasons about - the executor runs attacker code
//            in its own context via a trusted-but-attacker-controllable target - is exact.
//   On-chain (verified via read-only RPC, 2026-11-17):
//            Attack tx  0x8bf64bd802d039d03c63bf3614afc042f345e158ea0814c74be4b5b14436afb9
//                       from 0xb624e2b10b84a41687caec94bdd484e48d76b212 (attacker EOA),
//                       to   0x17e8ca1b4798b97602895f63206afcd1fc90ca5f (Furucombo proxy),
//                       block 11940588, 2021-02-27 17:07:12 UTC.
//   Sources: PeckShield "Cascading Trust"; coinspect learn-evm-attacks; cmichel replay
//            (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @dev Minimal ERC-20 surface the fixture drains (the real victims approved the proxy
///      for real tokens). Matches src/MockERC20 semantics for transferFrom.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Reads the handler proxy's current implementation. Furucombo trusted whitelisted
///         handler proxies; this is the resolution step before the delegatecall.
interface IHandlerProxy {
    function implementation() external view returns (address);
}

/// @title UninitializedHandlerProxy - the whitelisted-but-attacker-controllable handler.
/// @notice Models the Aave V2 proxy whose implementation was left uninitialized: anyone
///         could call `initialize` and set the implementation pointer. The Furucombo proxy
///         trusted this address as a registered handler, so whatever the attacker pointed
///         it at became code the executor would delegatecall into its own context.
contract UninitializedHandlerProxy {
    address public implementation;

    /// @dev No initializer guard - exactly the real defect (the live Aave implementation
    ///      was left uninitialized). Anyone can set (and re-set) the implementation.
    function initialize(address impl) external {
        implementation = impl;
    }
}

/// @title EvilHandler - the attacker's logic, run in the executor's context.
/// @notice When the Furucombo proxy delegatecalls this, `msg.sender` seen by the token is
///         the proxy itself, so a victim's standing approval to the proxy is spent.
contract EvilHandler {
    function drain(address token, address victim, address attacker, uint256 amount) external {
        IERC20(token).transferFrom(victim, attacker, amount);
    }
}

/// @title FurucomboProxyClone - minimized Furucombo-style combo executor.
/// @notice Runs user-chosen handlers by DELEGATECALL (Furucombo's combo-execution design).
///         Handlers are whitelisted ("registered"), but a whitelisted handler can be an
///         upgradeable proxy whose implementation the attacker controls (unguarded
///         initializer) - cascading trust. The resolved implementation runs in THIS
///         contract's storage/auth context, so it can spend standing approvals held by
///         users who trusted the proxy.
contract FurucomboProxyClone {
    address public owner;
    mapping(address => bool) public isValidHandler;

    error NotOwner();
    error HandlerNotWhitelisted();

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Owner registers a trusted handler (the real whitelist included the Aave proxy).
    function registerHandler(address handler) external {
        if (msg.sender != owner) revert NotOwner();
        isValidHandler[handler] = true;
    }

    /// @notice Execute a whitelisted handler: resolve its implementation and delegatecall it.
    /// @dev    The delegatecall is the teeth - the implementation runs as this executor.
    function exec(address handlerProxy, bytes calldata data) external {
        if (!isValidHandler[handlerProxy]) revert HandlerNotWhitelisted();
        address impl = IHandlerProxy(handlerProxy).implementation();
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "exec failed");
    }
}
