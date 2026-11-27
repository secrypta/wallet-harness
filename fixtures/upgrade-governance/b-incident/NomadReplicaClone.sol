// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./nomad-reinit-root-victim/PROVENANCE.md for the full block)
//   Vector:  upgrade-governance   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Nomad Bridge exploit, 2022-08-01, Ethereum, ~$190M drained. A routine
//            implementation UPGRADE of the Replica contract re-ran its initializer, which
//            set the trusted/committed root to zero and left the ZERO root marked as an
//            acceptable (proven) root. Because any message whose Merkle proof was never run
//            resolves to the zero root, every forged "process" call now passed the root
//            check - so anyone could submit a fabricated message and withdraw bridged funds.
//            It became a free-for-all: hundreds of copy-paste drainers followed the first.
//   Proof:   MECHANISM-LEVEL. Minimized reproduction of the upgrade-introduced defect: a
//            re-initialization that marks the zero root acceptable, after which process()
//            honors un-proven (forged) messages and releases custodied funds. The real
//            Merkle/optimistic-proof plumbing and cross-chain routing are abstracted.
//   On-chain (verified via read-only RPC, 2026-11-17 - eth_getTransactionByHash + block ts):
//            Attacker's first probe (0.01 WBTC in):
//              0xed26708a7335116bdb0673f32ace7c2f329fe3cd349e200447210f1721f335f0  block 15258799
//            Replica processes 100 WBTC out to the attacker:
//              0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460
//              from  0xa8c83b1b30291a3a1a118058b5445cc83041cd9d
//              to    0x5d94309e5a0090b165fa4181519701637b6daeba (Nomad Replica proxy)
//              block 15259101 (Ethereum), 2022-08-01 21:32:31 UTC.
//            Replica logic (vulnerable, re-initialized): 0xb92336759618f55bd0f8313bd843604592e27bd8.
//   Sources: samczsun; Paradigm; CertiK; Beosin; BlockSec (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title NomadReplicaClone - minimized Nomad Replica whose upgrade re-init trusts the 0 root.
/// @notice VULNERABLE: a routine implementation upgrade re-ran initialize(), which set the
///         committed root to zero AND marked the zero root as an acceptable (proven) root.
///         Since any message that was never actually proven resolves to the zero root,
///         acceptableRoot(0) == true makes every forged message pass process()'s root check,
///         so an attacker drains custodied funds with a fabricated message. The drain is a
///         direct consequence of an UPGRADE that re-initialized trusted state incorrectly.
contract NomadReplicaClone {
    // root => timestamp it became acceptable (0 == never acceptable)
    mapping(bytes32 => uint256) public confirmAt;
    bytes32 public committedRoot;
    bool public initialized;

    /// @notice The re-initialization the upgrade triggered. THE BUG: it marks the zero root
    ///         acceptable. (The real initializer set committedRoot = 0 and the zero root was
    ///         left in the "proven" state.)
    function initialize() external {
        require(!initialized, "already initialized");
        initialized = true;
        committedRoot = bytes32(0);
        confirmAt[bytes32(0)] = 1; // zero root marked acceptable -> message auth disabled
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        uint256 t = confirmAt[root];
        return t != 0 && t <= block.timestamp;
    }

    /// @notice Process a bridged message and release funds. `provenRoot` is the root the
    ///         message's (never-run) proof resolves to; for a forged message that is the zero
    ///         root, which acceptableRoot now accepts, so the release is authorized.
    /// @param provenRoot  the root the message proves against (0 for an un-proven/forged msg)
    /// @param token       the custodied asset to release
    /// @param to          recipient named in the (forged) message
    /// @param amount      amount named in the (forged) message
    function process(bytes32 provenRoot, address token, address to, uint256 amount) external {
        require(acceptableRoot(provenRoot), "!proven root");
        IERC20Like(token).transfer(to, amount);
    }
}
