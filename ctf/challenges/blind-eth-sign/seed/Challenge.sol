// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - a wallet that executes a transfer from an owner signature.
/// @notice This is the VULNERABLE version. Your job is to fix `executeWithSig` so a blind
///         signature cannot be replayed onto an attacker's transfer, WITHOUT breaking the
///         owner's own authorized transfer.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The bug: `signedHash` is an opaque digest supplied BY THE CALLER. The wallet recovers the
/// signer from it and, if it is the owner, pays out `(to, amount)` - but it never checks that
/// `signedHash` actually commits to `(to, amount, nonce)`. So one signature the owner was
/// tricked into blind-signing authorizes ANY transfer the caller names. `actionDigest` is the
/// structured digest the signature SHOULD be verified against.
contract Challenge {
    address public owner;
    address public asset;

    constructor() {
        owner = msg.sender;
    }

    function setAsset(address asset_) external {
        require(asset == address(0), "asset already set");
        asset = asset_;
    }

    /// @dev The structured digest a safe wallet derives from the action itself.
    function actionDigest(address to, uint256 amount, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), asset, to, amount, nonce));
    }

    function executeWithSig(
        bytes32 signedHash,
        bytes calldata sig,
        address to,
        uint256 amount,
        uint256 nonce
    ) external {
        // BUG: trusts a blind, caller-supplied digest and never ties it to (to, amount, nonce).
        nonce;
        require(_recover(signedHash, sig) == owner, "blind-eth-sign: bad signature");
        IERC20Transfer(asset).transfer(to, amount);
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
