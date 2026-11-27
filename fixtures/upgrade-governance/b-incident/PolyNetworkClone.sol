// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./poly-keeper-takeover-victim/PROVENANCE.md for the full block)
//   Vector:  upgrade-governance   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Poly Network exploit, 2021-08-10, Ethereum (+BNB Chain, Polygon), ~$611M - the
//            largest DeFi hack at the time. The EthCrossChainManager executed inbound
//            cross-chain messages by calling a target method with the manager's authority.
//            Nothing stopped a message from targeting the manager's OWN privileged storage
//            contract (EthCrossChainData), whose keeper-management function was `onlyOwner`
//            (owner == the manager). The attacker crafted a message that made the manager
//            call putCurEpochConPubKeyBytes, REPLACING the bridge "keeper" (the role that
//            authorizes withdrawals) with their own key. As the new keeper, they authorized
//            withdrawals that drained the lock-proxy vaults.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the governance/role-takeover: an
//            unguarded executed message reassigns the privileged keeper, after which the
//            attacker authorizes withdrawals and drains the vault. The real header/Merkle
//            verification and multi-chain plumbing are abstracted. (The drain here is a
//            PRIVILEGED-ROLE takeover, not an approval pull - that is what distinguishes it
//            from the malicious-calldata approval-drain cases.)
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Keeper takeover tx (putCurEpochConPubKeyBytes):
//              0xb1f70464bd95b774c6ce60fc706eb5f9e35cb5f06e6cfe7c17dcda46ffd59581
//              from 0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963 (attacker),
//              to   0x838bf9e95cb12dd76a54c9f9d2e3082eaf928270 (EthCrossChainManager),
//              block 12996659.
//            Drain (asset release) tx:
//              0xad7a2c70c958fcd3effbf374d0acf3774a9257577625ae4c838e24b0de17602a
//              from 0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963, to 0x838bf9e9...928270,
//              block 12996671 (Ethereum), 2021-08-10 09:51:02 UTC.
//            EthCrossChainData (keeper storage, owner == manager): 0xcf2afe102057ba5c16f899271045a0a37fcb10f2.
//   Sources: SlowMist; Mudit Gupta; BlockSec; CertiK; Valix (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @dev The manager's privileged storage: it holds the `keeper` (the role authorized to
///      approve withdrawals). putKeeper is gated to the owner, which is the manager.
contract PolyCrossChainData {
    address public owner; // the CrossChainManager
    address public keeper; // the role that authorizes withdrawals

    constructor(address _owner, address _initialKeeper) {
        owner = _owner;
        keeper = _initialKeeper;
    }

    function putKeeper(address newKeeper) external {
        require(msg.sender == owner, "only owner");
        keeper = newKeeper;
    }
}

/// @title PolyCrossChainManager - minimized Poly Network manager with an unguarded executor.
/// @notice VULNERABLE: verifyHeaderAndExecuteTx executes an inbound message by calling an
///         arbitrary target with arbitrary calldata using the manager's authority, and does
///         NOT prevent that target from being the manager's own privileged storage
///         (PolyCrossChainData). So a crafted message can call putKeeper and reassign the
///         keeper role. The governance defect is that a privileged role is reachable through
///         the unguarded execute path.
contract PolyCrossChainManager {
    PolyCrossChainData public data;

    constructor(address initialKeeper) {
        data = new PolyCrossChainData(address(this), initialKeeper);
    }

    function verifyHeaderAndExecuteTx(address target, bytes calldata callData) external {
        // No restriction on `target`/`callData`: a message may target the manager's own
        // keeper-management function, reassigning the privileged role.
        (bool ok, ) = target.call(callData);
        require(ok, "execute failed");
    }
}

/// @dev The lock-proxy vault: releases custodied assets only on the current keeper's say-so.
contract PolyLockProxy {
    PolyCrossChainData public data;
    IERC20Like public asset;

    constructor(PolyCrossChainData _data, IERC20Like _asset) {
        data = _data;
        asset = _asset;
    }

    /// @notice Withdraw is authorized by whoever is the CURRENT keeper. If the keeper role is
    ///         taken over, the attacker authorizes their own withdrawals.
    function withdraw(address to, uint256 amount) external {
        require(msg.sender == data.keeper(), "not keeper");
        asset.transfer(to, amount);
    }
}
