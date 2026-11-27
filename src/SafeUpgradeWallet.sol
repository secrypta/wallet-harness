// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeUpgradeWallet - the same upgradeable wallet WITH upgrade governance.
/// @notice Identical delegate-to-implementation design, but the implementation can no
///         longer be swapped in one instant call. An upgrade is a two-step, time-locked
///         action: the owner PROPOSES a new implementation, and it can only be APPLIED
///         after a fixed delay. During that window a separate `guardian` key can CANCEL a
///         pending upgrade. So a single compromised owner key cannot swap in a hostile
///         implementation and drain in the same breath: the delay gives the guardian (and
///         monitoring) time to veto, and an instant swap is simply impossible. This is the
///         defensive signal R10' checks for - upgradeability gated by a timelock/guardian.
contract SafeUpgradeWallet {
    address public owner;
    address public guardian;
    address public implementation;

    address public pendingImplementation;
    uint256 public pendingReadyAt;

    uint256 public constant UPGRADE_DELAY = 2 days;

    event UpgradeProposed(address indexed newImplementation, uint256 readyAt);
    event UpgradeExecuted(address indexed newImplementation);
    event UpgradeCancelled(address indexed cancelledImplementation);

    constructor(address owner_, address guardian_, address implementation_) {
        owner = owner_;
        guardian = guardian_;
        implementation = implementation_;
    }

    /// Step 1: owner proposes an upgrade. It does NOT take effect yet.
    function proposeUpgrade(address newImplementation) external {
        require(msg.sender == owner, "only owner");
        pendingImplementation = newImplementation;
        pendingReadyAt = block.timestamp + UPGRADE_DELAY;
        emit UpgradeProposed(newImplementation, pendingReadyAt);
    }

    /// Step 2: owner applies the upgrade - only after the timelock has fully elapsed. A
    /// compromised key cannot shortcut this: calling it early reverts.
    function executeUpgrade() external {
        require(msg.sender == owner, "only owner");
        require(pendingReadyAt != 0, "no pending upgrade");
        require(block.timestamp >= pendingReadyAt, "timelock not elapsed");
        implementation = pendingImplementation;
        emit UpgradeExecuted(pendingImplementation);
        pendingImplementation = address(0);
        pendingReadyAt = 0;
    }

    /// Guardian veto: a second, independent key cancels a pending (possibly hostile)
    /// upgrade during the delay window. This is the guardian half of the governance.
    function cancelUpgrade() external {
        require(msg.sender == guardian, "only guardian");
        address cancelled = pendingImplementation;
        pendingImplementation = address(0);
        pendingReadyAt = 0;
        emit UpgradeCancelled(cancelled);
    }

    /// Same execution path as the vulnerable wallet (delegatecall into the implementation).
    function execute(address token, address to, uint256 amount) external {
        require(msg.sender == owner, "only owner");
        (bool ok,) = implementation.delegatecall(
            abi.encodeWithSignature("execute(address,address,uint256)", token, to, amount)
        );
        require(ok, "exec failed");
    }
}
