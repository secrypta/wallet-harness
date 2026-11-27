// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the QNT reserve-pool drain via an EIP-7702-delegated ADMIN EOA
// (2026-04-28, 1,974.546547972979064297 QNT drained in the pinned tx, ~$124.9K, Ethereum mainnet).
// Authored in THIS repo (MIT). This is NOT a copy of any on-chain bytecode, decompilation, or
// third-party PoC. The documented MECHANISM is reproduced from authoritative write-ups and
// independently confirmed on-chain; see ./qnt-pool-7702-victim/PROVENANCE.md for incident facts
// (addresses, pinned exploit tx, on-chain verification, sources).
//
// Why this is DISTINCT from the other eip7702-delegation b-incidents (sven-eth, binance14,
// crimeenjoyor, inferno): those are account SWEEPERS - the malicious delegate itself moves the
// victim's own ETH/tokens out. Here the 7702-delegated account is a PRIVILEGED ADMIN EOA, and the
// delegate it points at (a "BatchExecutor") has a code-level access-control bug: its batch() entry
// is PUBLIC with no caller check. EIP-7702 makes the admin EOA callable by anyone, so any attacker
// drives the admin's delegated code to call a THIRD contract (the reserve pool) that trusts the
// admin by ADDRESS (msg.sender == admin). The drain target is the pool, not the EOA. Root cause is
// the missing access control on the delegated batch executor combined with address-based trust under
// 7702 - a different code-level surface from a pure sweeper.
//
// As elsewhere in this corpus, the "code runs as the account" 7702 semantics is modeled EXPLICITLY
// via delegatecall (no vm.signDelegation dependency) so the fixture is deterministic on any
// toolchain. The verdict is derived from the real outcome (the pool's reserves end up at the
// attacker), not hardcoded.

/// @dev Minimal ERC20 (reserve token stand-in for QNT). Self-contained; no external dependency.
contract MockReserveToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @title QntReservePool - a pool that trusts its admin by ADDRESS.
/// @notice Models the real pool's address-based trust: forwardTransaction() only checks that the
///         caller IS the registered admin address. It has no idea the admin is an EIP-7702 EOA whose
///         code was handed to an unpermissioned batch executor, so it faithfully honors any call that
///         arrives from the admin's address.
contract QntReservePool {
    address public admin;
    MockReserveToken public token;

    constructor(address admin_, MockReserveToken token_) {
        admin = admin_;
        token = token_;
    }

    function _isAdmin(address who) internal view returns (bool) {
        return who == admin;
    }

    /// @dev The privileged reserve-movement entrypoint. Address-based trust only.
    function forwardTransaction(address to, uint256 amount) external {
        require(_isAdmin(msg.sender), "not admin");
        token.transfer(to, amount);
    }
}

/// @title VulnerableBatchExecutorDelegate - the code the admin EOA delegated to under EIP-7702.
/// @notice Real on-chain BatchExecutor exposed batch(address[],bytes[]) (selector 0xf38f59d7) as a
///         PUBLIC function with NO access control, looping low-level calls to arbitrary targets with
///         arbitrary calldata. Once an admin EOA points its 7702 code here, anyone can call batch()
///         on the EOA and thereby act AS the admin against any contract that trusts the admin.
contract VulnerableBatchExecutorDelegate {
    /// @dev No access control: any caller may drive arbitrary calls in the account's context.
    function batch(address[] calldata targets, bytes[] calldata data) external {
        require(targets.length == data.length, "len");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call(data[i]);
            require(ok, "batch-call-failed");
        }
    }
}

/// @title AdminEoaAccount - the privileged admin EOA, 7702-delegated to the batch executor.
/// @notice Registered as the pool's admin. After installing the (unpermissioned) batch-executor
///         delegate, running its code in the account's context lets ANY caller (the attacker) issue
///         calls that the account authors - so the pool's admin check passes for attacker-driven
///         reserve moves.
contract AdminEoaAccount {
    address public delegate;

    function installDelegation(address delegate_) external {
        delegate = delegate_;
    }

    /// @dev Activate the delegate in this account's context (delegatecall models 7702 "run delegate
    ///      code as the account"). Invokable by anyone - exactly the point: the batch executor it
    ///      runs has no caller check, so there is no gate here either.
    function activate(bytes calldata data) external returns (bytes memory) {
        require(delegate != address(0), "no delegation");
        (bool ok, bytes memory ret) = delegate.delegatecall(data);
        require(ok, "delegate execution failed");
        return ret;
    }

    receive() external payable {}
}
