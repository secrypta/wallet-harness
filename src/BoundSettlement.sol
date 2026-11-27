// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Settle {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title BoundSettlement - DEFENSIVE signature verifier (R5, safe).
/// @notice Authorizes a transfer only from a fully BOUND EIP-712 signature: the digest is
///         bound to this contract via a domain separator (chainId + verifyingContract), to a
///         single use via the owner's nonce, and to a time window via a deadline. The same
///         signature therefore cannot be replayed (nonce is consumed), cannot be reused on a
///         clone / another chain (domain separator differs) and cannot be used after expiry.
///         Rule R5 must stay silent here (0 false positives). A reverted settle means the
///         order was unbound/replayed/expired - never a malformed-signature accident:
///         ecrecover is checked non-zero and against the owner.
contract BoundSettlement {
    struct Order {
        address owner; // asset owner / signer
        address token; // ERC-20 being moved
        uint256 amount; // amount authorized by this order
        address recipient; // where the order sends the assets
        uint256 nonce; // owner's current nonce (single-use binding)
        uint256 deadline; // expiry (time binding)
    }

    mapping(address => uint256) public nonces;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address owner,address token,uint256 amount,address recipient,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR; // contract/chain binding

    event Settled(address indexed owner, address indexed token, address indexed recipient, uint256 amount);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BoundSettlement")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function hashOrder(Order calldata o) public view returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(ORDER_TYPEHASH, o.owner, o.token, o.amount, o.recipient, o.nonce, o.deadline));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function settle(Order calldata o, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= o.deadline, "BoundSettlement: order expired");
        require(o.nonce == nonces[o.owner], "BoundSettlement: bad nonce");
        address recovered = ecrecover(hashOrder(o), v, r, s);
        require(recovered != address(0) && recovered == o.owner, "BoundSettlement: bad signature");
        nonces[o.owner]++; // consume the nonce: the signature is now spent
        IERC20Settle(o.token).transferFrom(o.owner, o.recipient, o.amount);
        emit Settled(o.owner, o.token, o.recipient, o.amount);
    }
}
