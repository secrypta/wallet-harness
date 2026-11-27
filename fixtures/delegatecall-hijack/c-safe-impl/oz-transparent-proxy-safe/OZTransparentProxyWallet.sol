// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the delegatecall-hijack vector (precision check).
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// OZ `TransparentUpgradeableProxy` is the canonical transparent-proxy pattern. It USES
// `delegatecall` (every non-admin call is forwarded to the ERC-1967 implementation), and
// upgrades are routed through a dedicated `ProxyAdmin` (owned by the governance owner): only
// the admin may call the proxy's `upgradeToAndCall`, and any other caller is delegatecalled to
// the implementation. The delegatecall-hijack vector (Parity/Bybit) is an owner-approved
// operation delegatecalling a CALLER-CHOSEN target; this proxy has no such sink: the only
// delegatecall target is the managed implementation slot, the sink cannot be redirected except
// by the ProxyAdmin owner, and the logic executes owner operations via a plain `call`.
//
// Distinct from `oz-erc1967-proxy-safe` (bare ERC1967/UUPS) and `solady-uups-proxy-safe`
// (Solady UUPS): this is the TRANSPARENT-proxy admin pattern (external ProxyAdmin, admin/user
// call-routing). The only authored code is this thin logic (stored `owner`, owner-only
// `execute` via plain `call`), plus a V2 to prove a legit admin upgrade still applies.

/// @title TUPWallet - a minimal logic implementation to run behind TransparentUpgradeableProxy.
contract TUPWallet {
    address public owner;
    uint256 public version;

    function initialize(address owner_) external {
        require(owner == address(0), "initialized");
        owner = owner_;
        version = 1;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// @notice Owner-approved operation executed via a PLAIN `call` (no delegatecall mode).
    function execute(address to, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }
}

/// @title TUPWalletV2 - a benign upgrade proving a legit admin-routed upgrade applies.
contract TUPWalletV2 {
    address public owner;
    uint256 public version;

    function bump() external {
        version = 2;
    }
}
