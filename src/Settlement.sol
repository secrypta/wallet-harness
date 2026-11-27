// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Settle {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Settlement - minimal marketplace-style settlement of a signed order.
/// @notice Models the shape behind signature-phishing: a signed off-chain ORDER (not a
///         transaction from the owner) authorizes moving the owner's assets. The owner has
///         pre-approved this settlement contract for their tokens (as marketplace users
///         routinely do); authority to move a specific amount to a specific recipient then
///         comes from the owner's EIP-712 signature over an Order.
///         The danger is not the approval but WHICH order the owner is lured into signing:
///         an all-asset order to the attacker drains everything; a scoped order does not.
contract Settlement {
    struct Order {
        address owner; // asset owner / signer
        address token; // ERC-20 being moved
        uint256 amount; // amount authorized by this order
        address recipient; // where the order sends the assets
        uint256 nonce; // owner's current nonce
        uint256 deadline; // expiry
    }

    mapping(address => uint256) public nonces;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address owner,address token,uint256 amount,address recipient,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    event Settled(address indexed owner, address indexed token, address indexed recipient, uint256 amount);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Settlement")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function hashOrder(Order calldata o) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ORDER_TYPEHASH, o.owner, o.token, o.amount, o.recipient, o.nonce, o.deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @notice Executes an order if the owner's signature over it is valid. Guards are
    ///         strict so a reverted settlement means "this order was not authorized", never
    ///         a malformed-signature accident: deadline in the future; nonce matches;
    ///         ecrecover is non-zero and equals the order's owner; nonce consumed after.
    function settle(Order calldata o, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= o.deadline, "Settlement: order expired");
        require(o.nonce == nonces[o.owner], "Settlement: bad nonce");
        address recovered = ecrecover(hashOrder(o), v, r, s);
        require(recovered != address(0) && recovered == o.owner, "Settlement: bad signature");
        nonces[o.owner]++;
        IERC20Settle(o.token).transferFrom(o.owner, o.recipient, o.amount);
        emit Settled(o.owner, o.token, o.recipient, o.amount);
    }
}
