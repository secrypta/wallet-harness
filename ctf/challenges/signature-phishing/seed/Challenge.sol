// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - a settlement wallet that fills owner-signed orders.
/// @notice This is the VULNERABLE version. Your job is to fix `hashOrder` so a signature
///         made for one order cannot be reused for a different amount/recipient, WITHOUT
///         breaking legitimately signed orders.
///
///         Keep the function signatures exactly as-is - the hidden grader calls `fillOrder`
///         and `hashOrder` by these names and arguments. You may change only the body of
///         `hashOrder`.
///
/// The intended use: the owner signs an order {token, amount, recipient, nonce} off-chain;
/// a relayer submits it and the wallet pays out. The bug is that `hashOrder` leaves `amount`
/// and `recipient` OUT of the signed digest, so the owner's signature for a small, scoped
/// order is equally valid for a full-balance order to an attacker.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// @dev Digest the owner signs and the wallet verifies. The grader signs whatever this
    ///      returns for the legitimate order, so it stays the single source of truth.
    function hashOrder(address token, uint256 amount, address recipient, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        // BUG: amount and recipient are NOT bound into the digest.
        amount;
        recipient;
        return keccak256(abi.encode(address(this), token, nonce));
    }

    function fillOrder(
        address token,
        uint256 amount,
        address recipient,
        uint256 nonce,
        bytes calldata sig
    ) external {
        bytes32 digest = hashOrder(token, amount, recipient, nonce);
        require(_recover(digest, sig) == owner, "signature-phishing: bad signature");
        IERC20Transfer(token).transfer(recipient, amount);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
