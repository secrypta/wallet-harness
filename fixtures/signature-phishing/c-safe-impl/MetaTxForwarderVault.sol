// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC2771Context} from "../../vendor/oz/metatx/ERC2771Context.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @title MetaTxForwarderVault - a meta-transaction recipient whose per-user funds move only on
///        the user's own relayed intent. Real-safe (tier c) vehicle for signature-phishing.
/// @notice signature-phishing has a gasless meta-transaction sub-vector: a relayer submits a
///         `ForwardRequest` the user signed off-chain. The safety-critical part is the forwarder's
///         EIP-712 signature verification, which binds the relayed call to the signer so a forged
///         request cannot impersonate the victim. That verifier is the UNMODIFIED OpenZeppelin
///         `ERC2771Forwarder` (fixtures/vendor/oz/metatx/, MIT, pinned v5.1.0; see
///         fixtures/vendor/PROVENANCE.md). This vault trusts that forwarder and attributes each
///         withdrawal to the forwarded signer via OZ `ERC2771Context._msgSender()`; it adds ONLY a
///         per-user balance ledger and a withdrawal scoped to the caller's own balance.
///
///         Distinct from the existing signature-phishing holdouts (OZ SignatureChecker, OZ
///         EIP712+ECDSA, Solady ERC1271 - all direct on-chain signature checks): this exercises the
///         canonical META-TRANSACTION relay path (ERC-2771 forwarder), a different real surface wal
///         was never tuned against.
contract MetaTxForwarderVault is ERC2771Context {
    address public immutable token;
    mapping(address => uint256) public balanceOf;

    constructor(address trustedForwarder_, address token_) ERC2771Context(trustedForwarder_) {
        token = token_;
    }

    /// @notice Test-only: credit `user` with `amount` of the vault's holdings (no access control
    ///         on purpose; fixtures only). The test mints the matching tokens into the vault.
    function fund(address user, uint256 amount) external {
        balanceOf[user] += amount;
    }

    /// @notice Withdraw `amount` to `to` from the CALLER's own balance. The caller is the forwarded
    ///         signer (`_msgSender()`), so only a request the user actually signed can move the
    ///         user's funds. A forged request never reaches here - the forwarder rejects it.
    function withdraw(address to, uint256 amount) external {
        address user = _msgSender();
        require(balanceOf[user] >= amount, "vault: insufficient balance");
        balanceOf[user] -= amount;
        require(IERC20Min(token).transfer(to, amount), "vault: transfer failed");
    }
}
