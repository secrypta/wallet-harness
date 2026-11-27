// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "../../vendor/solady/EIP712.sol";
import {SignatureCheckerLib} from "../../vendor/solady/SignatureCheckerLib.sol";

/// @title SoladyTypedSigVault - safe, typed-signature-gated withdrawal vehicle (Solady).
/// @notice blind-eth-sign tier (c) real-safe HOLDOUT vehicle. The safety-critical logic - the
///         EIP-712 domain/digest (`EIP712._hashTypedData`) and the signature validation
///         (`SignatureCheckerLib.isValidSignatureNowCalldata`, with ECDSA malleability/zero-address
///         safety underneath) - is UNMODIFIED Solady (fixtures/vendor/solady/, MIT, pinned commit;
///         see fixtures/vendor/PROVENANCE.md). This contract adds ONLY a typed `Withdrawal` struct,
///         a replay nonce, and a withdrawal gated on that check.
///
///         There is NO raw-hash / eth_sign entrypoint: funds release ONLY against a signature over
///         the FULLY-TYPED, domain-separated digest. A "blind" signature over an opaque raw hash
///         (the eth_sign danger) does not match the typed digest, so the Solady verifier rejects it
///         (recovered signer != owner) and nothing moves.
///
///         Distinct from the existing blind-eth-sign holdouts: `oz-clearsign-safe` uses OpenZeppelin
///         EIP712+ECDSA and `permit2-sigverify-safe` uses Uniswap Permit2's verifier. This fixture
///         exercises the same clear-signing defense on the INDEPENDENT Solady codebase the wal
///         detectors were NEVER tuned against (a genuine `holdout` precision test).
contract SoladyTypedSigVault is EIP712 {
    address public immutable owner; // the account whose typed signature authorizes a withdrawal
    address public immutable token; // the held ERC-20
    uint256 public nonce;           // consumed per authorized withdrawal (anti-replay)

    bytes32 public constant WITHDRAWAL_TYPEHASH =
        keccak256("Withdrawal(address to,uint256 amount,uint256 nonce)");

    constructor(address owner_, address token_) {
        owner = owner_;
        token = token_;
    }

    /// @dev Required Solady EIP712 override: the domain name/version for the typed digest.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        return ("SoladyTypedSigVault", "1");
    }

    /// @notice The EIP-712 typed digest the owner must have signed to authorize this withdrawal.
    ///         Decodable and scoped: it names the exact recipient, amount and nonce - not an
    ///         opaque blob a victim could be tricked into blind-signing.
    function withdrawDigest(address to, uint256 amount, uint256 nonce_) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(WITHDRAWAL_TYPEHASH, to, amount, nonce_));
        return _hashTypedData(structHash);
    }

    /// @notice Release `amount` to `to` iff `signature` is the owner's signature over the TYPED
    ///         digest for the current nonce. A blind/raw-hash signature yields a different
    ///         recovered signer and is rejected by Solady's SignatureCheckerLib.
    function withdraw(address to, uint256 amount, bytes calldata signature) external {
        bytes32 digest = withdrawDigest(to, amount, nonce);
        require(
            SignatureCheckerLib.isValidSignatureNowCalldata(owner, digest, signature),
            "vault: bad signature"
        );
        unchecked {
            ++nonce;
        }
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }
}
