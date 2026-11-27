// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AudiusGovernanceClone - minimized offline clone of the governance-takeover drain of
///        the Audius Governance proxy (incident 2022-07-23).
/// @notice NOT our toy: a faithful, minimized reproduction of the affected contract's exploited
///         surface. The Audius Governance contract was an upgradeable proxy whose `initialize`
///         could be called by anyone on the live proxy (uninitialized-proxy / storage-layout
///         flaw, no re-init guard). The attacker called `initialize` to install themselves as
///         the controlling party, then pushed a malicious governance proposal that transferred
///         the treasury's tokens out. Root cause: a privileged governance controller settable by
///         a single unguarded call, with no timelock / guardian gate. Only that surface is
///         modeled here. Provenance (tx hashes, addresses, source) in
///         audius-governance-victim/PROVENANCE.md. Offline only - no network, no live RPC.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.

/// @dev Minimal treasury token (18 decimals) the governance module custodies.
contract GovTreasuryToken {
    string public name = "Audius (minimized incident clone)";
    string public symbol = "AUDIO";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "AUDIO: insufficient balance");
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/// @dev Minimized upgradeable governance module. `execute` is a legitimate governance power
///      (move treasury per an approved proposal) gated on the controller. THE BUG: `initialize`
///      installs that controller with NO already-initialized guard, NO timelock and NO guardian,
///      so a single unguarded call on the live proxy seizes governance.
contract AudiusGovernanceClone {
    address public controller; // the party allowed to execute governance actions
    GovTreasuryToken public immutable treasury;

    constructor(GovTreasuryToken treasury_) {
        treasury = treasury_;
    }

    /// @notice BUG: callable by anyone, any time (no `initialized` guard / no timelock).
    function initialize(address controller_) external {
        controller = controller_;
    }

    /// @notice Governance-controlled treasury move (models a passed proposal).
    function execute(address to, uint256 amount) external {
        require(msg.sender == controller, "gov: not controller");
        treasury.transfer(to, amount);
    }
}
