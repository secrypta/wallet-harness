// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Challenge - reference FIX for the blind-eth-sign vector.
/// @notice Never trust the caller-supplied `signedHash`. Derive the digest from the action
///         (`actionDigest(to, amount, nonce)`) and verify the signature against that, so a
///         signature only ever authorizes the exact transfer the signer committed to. The
///         owner's own authorized transfer still executes; a replay with a different
///         `to`/`amount` recovers a non-owner and reverts.
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
        // FIX: ignore the blind caller-supplied hash; verify against the digest derived from
        //      the action itself.
        signedHash;
        bytes32 digest = actionDigest(to, amount, nonce);
        require(_recover(digest, sig) == owner, "blind-eth-sign: bad signature");
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
