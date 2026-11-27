// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1271} from "../../vendor/solady/ERC1271.sol";

/// @title SoladyERC1271Wallet - concrete smart wallet over the UNMODIFIED vendored Solady
///        ERC1271 (ERC-7739 nested-EIP-712) signature verification.
/// @notice Real-safe HOLDOUT vehicle for the signature-phishing vector. The signature check
///         that gates every withdrawal - `isValidSignature` with Solady's ERC-7739 nested
///         EIP-712 scheme (anti-replay, cross-account-safe) and Solady's SignatureCheckerLib/
///         ECDSA under it - is unmodified Solady code (fixtures/vendor/solady/{ERC1271,EIP712,
///         SignatureCheckerLib}.sol; see fixtures/vendor/PROVENANCE.md). This subclass adds only
///         the two required override hooks and a signature-gated `withdraw`; it changes none of
///         the verification logic.
///
///         Solady is an independent implementation (not OpenZeppelin) the wal detectors were
///         NOT tuned against - a genuine `holdout` precision test: the harness must stay silent
///         (BLOCKED) when a forged/phished signature is rejected by this unseen safe code.
contract SoladyERC1271Wallet is ERC1271 {
    address public immutable signer;
    uint256 public nonce;

    constructor(address signer_) {
        signer = signer_;
    }

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        return ("SoladySafeWallet (holdout)", "1");
    }

    /// @dev The single owner key `isValidSignature` checks against.
    function _erc1271Signer() internal view override returns (address) {
        return signer;
    }

    receive() external payable {}

    /// @notice Withdraw gated by a valid owner signature over (to, amount, nonce). A forged or
    ///         replayed signature does not validate, so the withdrawal cannot proceed.
    function withdraw(address to, uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encode(to, amount, nonce));
        require(isValidSignature(hash, signature) == bytes4(0x1626ba7e), "ERC1271: bad signature");
        nonce++;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "withdraw failed");
    }
}
