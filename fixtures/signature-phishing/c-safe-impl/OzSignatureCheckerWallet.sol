// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "../../vendor/oz/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "../../vendor/oz/utils/cryptography/SignatureChecker.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @title OzSignatureCheckerWallet - signature-gated wallet whose every withdrawal is
///        authorized by the UNMODIFIED OpenZeppelin `SignatureChecker` over an OZ `EIP712`
///        typed digest. Real-safe (tier c) vehicle for the signature-phishing vector.
/// @notice The safety-critical logic - the EIP-712 domain/digest (`EIP712._hashTypedDataV4`)
///         and the signature validation (`SignatureChecker.isValidSignatureNow`, which also
///         supports ERC-1271 contract signers, with ECDSA zero-address/malleability safety
///         underneath) - is vendored byte-identical OpenZeppelin v5.1.0
///         (fixtures/vendor/oz/, see fixtures/vendor/PROVENANCE.md). This contract adds only
///         a typed `Withdraw` struct, a replay nonce, and a withdrawal gated on that check.
///         A forged/phished signature does not validate, so no authorization is produced and
///         nothing leaves the wallet: the harness must stay silent (BLOCKED). Distinct from
///         `oz-sig-safe` (which uses bare `ECDSA.recover` under a scoped-order policy): this
///         exercises OZ's higher-level `SignatureChecker` (ERC-1271-aware) path.
contract OzSignatureCheckerWallet is EIP712 {
    address public immutable signer;
    mapping(uint256 => bool) public usedNonce;

    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address token,address to,uint256 amount,uint256 nonce)");

    constructor(address signer_) EIP712("OzSignatureCheckerWallet", "1") {
        signer = signer_;
    }

    /// @dev The typed digest an authorizing signature must cover (decodable, scoped: it names
    ///      the exact token, recipient, amount and nonce - not an opaque blob).
    function withdrawDigest(address token, address to, uint256 amount, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, token, to, amount, nonce));
        return _hashTypedDataV4(structHash);
    }

    /// @notice Withdraw `amount` of `token` to `to`, only if `signature` is a valid signature
    ///         by `signer` over the typed digest. Authority comes solely from that check; a
    ///         forged or phished signature fails validation and the call reverts.
    function withdraw(address token, address to, uint256 amount, uint256 nonce, bytes calldata signature)
        external
    {
        require(!usedNonce[nonce], "wallet: nonce used");
        bytes32 digest = withdrawDigest(token, to, amount, nonce);
        require(SignatureChecker.isValidSignatureNow(signer, digest, signature), "wallet: bad signature");
        usedNonce[nonce] = true;
        require(IERC20Min(token).transfer(to, amount), "wallet: transfer failed");
    }
}
