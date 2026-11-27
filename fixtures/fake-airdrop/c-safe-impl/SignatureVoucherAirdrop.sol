// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "../../vendor/oz/utils/cryptography/EIP712.sol";
import {ECDSA} from "../../vendor/oz/utils/cryptography/ECDSA.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @title SignatureVoucherAirdrop - safe, signature-voucher-gated airdrop claim vehicle.
/// @notice fake-airdrop tier (c) real-safe HOLDOUT vehicle. Each claim is authorized by a voucher
///         the airdrop AUTHORITY signed off-chain over a FULLY-TYPED EIP-712 `Claim(address
///         account,uint256 amount)` digest; the claim releases exactly the authorized allocation
///         to the authorized account, once. The safety-critical logic - the EIP-712 domain/digest
///         (`EIP712._hashTypedDataV4`) and signature recovery (`ECDSA.recover`, with
///         zero-address/malleability safety) - is UNMODIFIED OpenZeppelin v5.1.0
///         (fixtures/vendor/oz/, MIT; see fixtures/vendor/PROVENANCE.md). This contract adds ONLY
///         the typed Claim struct, a per-account claimed flag, and the gated transfer.
///
///         This is the canonical signature-voucher airdrop pattern (as used by many real token
///         distributions), distinct from the Merkle-proof holdouts (`oz-merkleproof-safe`,
///         `solady-merkle-airdrop-safe`): the inclusion check here is an AUTHORITY SIGNATURE, not
///         a Merkle proof. A forged voucher (not signed by the authority) does not recover to the
///         authority and is rejected; a "fake airdrop" cannot mint itself a claim.
contract SignatureVoucherAirdrop is EIP712 {
    address public immutable token;
    address public immutable authority;
    mapping(address => bool) public claimed;

    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(address account,uint256 amount)");

    error AlreadyClaimed();
    error BadVoucher();

    event Claimed(address indexed account, uint256 amount);

    constructor(address token_, address authority_) EIP712("SignatureVoucherAirdrop", "1") {
        token = token_;
        authority = authority_;
    }

    /// @notice The typed voucher digest the AUTHORITY must have signed to authorize a claim.
    function claimDigest(address account, uint256 amount) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, account, amount));
        return _hashTypedDataV4(structHash);
    }

    /// @notice Claim `amount` for `account` iff `signature` is the authority's signature over the
    ///         typed voucher. A forged voucher recovers to a non-authority signer and reverts.
    function claim(address account, uint256 amount, bytes calldata signature) external {
        if (claimed[account]) revert AlreadyClaimed();
        address signer = ECDSA.recover(claimDigest(account, amount), signature);
        if (signer != authority) revert BadVoucher();
        claimed[account] = true;
        require(IERC20Min(token).transfer(account, amount), "transfer failed");
        emit Claimed(account, amount);
    }
}
