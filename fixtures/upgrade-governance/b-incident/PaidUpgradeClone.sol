// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PaidUpgradeClone - minimized OFFLINE clone of the upgradeable token drained in the
///        PAID Network incident (2021-03-05), for the upgrade-governance (b) real-incident
///        fixture.
/// @notice NOT our toy: a faithful, minimized reproduction of the affected token's RELEVANT
///         surface. PAID's ERC-20 was an upgradeable (proxy) token whose implementation could
///         be swapped by a SINGLE key (the original deployer's). That key was compromised;
///         the attacker swapped in an implementation - absent from the audited version - that
///         could burn and re-mint, then minted ~59.47M PAID to themselves and sold into the
///         market. The code itself was clean; the defect was an unguarded single-key upgrade
///         (no timelock, no guardian, no multisig). Only the proxy upgrade path + a mint-
///         capable malicious implementation needed to replay that are modeled here; the full
///         token/vesting logic is omitted. Provenance (contract address, figures, post-mortems)
///         in PROVENANCE.md. Offline only - no network, no live RPC. Build/run in Docker.
///
/// Verdict is derived from the real OUTCOME (attacker's balance / total supply moved by the
/// post-upgrade mint), never from addresses.

/// @dev Storage layout shared by the proxy and every logic implementation so that a
///      delegatecall from the proxy reads/writes the proxy's own slots. Any implementation
///      MUST inherit this and add no state before it.
contract PaidTokenStorage {
    address public owner; // slot 0: the single upgrade key (deployer key in the incident)
    address public implementation; // slot 1: current logic
    uint256 public totalSupply; // slot 2
    mapping(address => uint256) public balanceOf; // slot 3
}

/// @notice The upgradeable token proxy. Holds balances; routes logic calls to `implementation`
///         via delegatecall. A single key can swap the implementation INSTANTLY.
contract PaidTokenProxy is PaidTokenStorage {
    event Upgraded(address indexed newImplementation);

    constructor(address owner_, address implementation_, address[] memory holders, uint256[] memory amounts) {
        owner = owner_;
        implementation = implementation_;
        for (uint256 i = 0; i < holders.length; i++) {
            balanceOf[holders[i]] = amounts[i];
            totalSupply += amounts[i];
        }
    }

    /// VULNERABLE upgrade path: single key, instant effect. No timelock / guardian / multisig
    /// stands between a compromised key and a hostile implementation. This is exactly the
    /// unguarded-upgrade defect of the incident.
    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "only owner");
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "no impl");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

/// @title BenignPaidLogic - the honest, audited implementation.
/// @notice Plain ERC-20 transfer over the shared storage. There is NO path that mints to an
///         arbitrary account - that capability did not exist in the audited code.
contract BenignPaidLogic is PaidTokenStorage {
    event Transfer(address indexed from, address indexed to, uint256 value);

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/// @title MaliciousPaidLogic - the implementation swapped in via the compromised upgrade key.
/// @notice Adds the mint path absent from the audited code: `pwn` mints an arbitrary amount to
///         an arbitrary account (the attacker). Installing this IS the drain - holders' stake
///         is diluted/seized by the freshly minted supply. Mirrors the documented PAID path
///         (burn + re-mint ~59.47M to the attacker).
contract MaliciousPaidLogic is PaidTokenStorage {
    event Transfer(address indexed from, address indexed to, uint256 value);

    function pwn(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
