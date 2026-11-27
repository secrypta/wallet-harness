// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the signature-phishing vector.
/// @notice Bind every field the order authorizes into the signed digest. A signature is now
///         valid only for the exact {token, amount, recipient, nonce} it was made for, so it
///         cannot be lifted onto a full-balance order to an attacker. A legitimately signed
///         order still settles for its own amount and recipient.
contract Challenge {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function hashOrder(address token, uint256 amount, address recipient, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        // FIX: bind amount and recipient into the digest alongside token and nonce.
        return keccak256(abi.encode(address(this), token, amount, recipient, nonce));
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
