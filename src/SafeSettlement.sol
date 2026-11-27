// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "../fixtures/vendor/oz/utils/cryptography/EIP712.sol";
import {ECDSA} from "../fixtures/vendor/oz/utils/cryptography/ECDSA.sol";

interface IERC20Settle {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title SafeSettlement - signature-phishing tier (c): a settlement built on the REAL
///        OpenZeppelin signature stack with a scoped, decode-first policy.
/// @notice The signature verification is unmodified OpenZeppelin: `EIP712` for the typed
///         domain/digest and `ECDSA.recover` (zero-address and malleability safe). On top
///         of that real crypto this contract enforces a defensive policy that makes
///         signature-phishing non-settleable:
///           * only a DECODABLE EIP-712 `Order` is accepted - there is no entrypoint that
///             settles a blind `eth_sign` 32-byte hash, so an opaque-hash lure has no path;
///           * the recipient must be an allow-listed, known counterparty - an order paying
///             an untrusted attacker is rejected;
///           * the amount must be within a scoped cap - an all-asset order is rejected even
///             to a known recipient.
///         So a blind / all-asset phishing order reverts here regardless of a valid
///         signature, while a genuine scoped order to a known counterparty settles.
contract SafeSettlement is EIP712 {
    struct Order {
        address owner; // asset owner / signer
        address token; // ERC-20 being moved
        uint256 amount; // amount authorized by this order
        address recipient; // where the order sends the assets
        uint256 nonce; // owner's current nonce
        uint256 deadline; // expiry
    }

    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address owner,address token,uint256 amount,address recipient,uint256 nonce,uint256 deadline)"
    );

    uint256 public immutable scopedCap; // per-order upper bound (rejects all-asset orders)
    mapping(address => uint256) public nonces;
    mapping(address => bool) public knownRecipient; // allow-listed counterparties

    event RecipientAllowed(address indexed recipient);
    event Settled(address indexed owner, address indexed token, address indexed recipient, uint256 amount);

    constructor(uint256 scopedCap_) EIP712("SafeSettlement", "1") {
        scopedCap = scopedCap_;
    }

    /// @notice Toy allow-listing of a verified counterparty (no access control; fixtures only).
    function allowRecipient(address recipient) external {
        knownRecipient[recipient] = true;
        emit RecipientAllowed(recipient);
    }

    /// @notice The EIP-712 typed digest for an order, using the real OZ domain separator.
    ///         Signers sign this; there is deliberately no blind-hash entrypoint.
    function hashOrder(Order calldata o) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ORDER_TYPEHASH, o.owner, o.token, o.amount, o.recipient, o.nonce, o.deadline)
        );
        return _hashTypedDataV4(structHash);
    }

    /// @notice Settle a signed order under the scoped policy. A reverted settlement means
    ///         the order was not authorized by policy (or not validly signed), never a
    ///         malformed-signature accident: OZ `ECDSA.recover` already rejects zero/ malleable
    ///         signatures, and the scoped checks below reject blind/all-asset phishing orders.
    function settle(Order calldata o, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= o.deadline, "SafeSettlement: order expired");
        require(o.nonce == nonces[o.owner], "SafeSettlement: bad nonce");

        // Real OZ signature verification over the decodable typed order.
        address recovered = ECDSA.recover(hashOrder(o), v, r, s);
        require(recovered == o.owner, "SafeSettlement: bad signature");

        // Scoped, decode-first policy: known recipient and bounded amount only.
        require(knownRecipient[o.recipient], "SafeSettlement: recipient not allow-listed");
        require(o.amount <= scopedCap, "SafeSettlement: order exceeds scoped cap");

        nonces[o.owner]++;
        IERC20Settle(o.token).transferFrom(o.owner, o.recipient, o.amount);
        emit Settled(o.owner, o.token, o.recipient, o.amount);
    }
}
