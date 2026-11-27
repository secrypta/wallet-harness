// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Lumi Finance / Sodium smart-account drain
// (2026-07-13, Arbitrum One, ~$270K USDT0 per Verichains).
// Authored in THIS repo (MIT). This is NOT a copy of the on-chain Sodium account implementation
// and NOT a copy of any third-party PoC. The documented MECHANISM is reproduced from the
// authoritative Verichains write-up; see ./sodium-erc1271-victim/PROVENANCE.md for the incident
// facts (attacker, implementation contract, example tx hashes, loss, sources).
//
// Root cause (per Verichains): the account's ERC-1271 signature path let the UserOp NAME the
// signer contract. A type-0x01 signature was laid out as `0x01 || signerContract(20) || inner`,
// and validation trusted `isValidSignature` from that attacker-named contract. The attacker's
// contract returned the ERC-1271 magic value for an arbitrary one-byte payload, so validation
// passed with NO owner authorization. The session check then compared `sessionKey` (from callData)
// against `signer` (from the signature) - both attacker-controlled - and, with no configured safe
// session, returned validation success. Separately, the same validation turned attacker-controlled
// `paymasterAndData` into a persistent max ERC-20 approval to the attacker's contract. Because
// validation returned success (not failure), EntryPoint did not roll the approval back.
//
// R15 anchor axis: the trusted ERC-1271 signer is decoded from the caller-supplied `signature`
// (it is not an immutable / owner-configured signer), so an attacker names their own permissive
// contract. Offline fixture, never deployed.

interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

contract SodiumAccountClone {
    bytes4 private constant MAGIC = 0x1626ba7e;

    address public owner;        // the real account owner (never consulted on the drain path)
    address public entryPoint;

    constructor(address owner_, address entryPoint_) {
        owner = owner_;
        entryPoint = entryPoint_;
    }

    /// @notice Minimized ERC-4337-style validation. `signature` and `paymasterAndData` are
    ///         attacker-controlled UserOp fields. The signer contract is named INSIDE `signature`.
    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature,
        bytes calldata paymasterAndData
    ) external returns (uint256 validationData) {
        require(msg.sender == entryPoint, "only entrypoint");

        // sigType 0x01 => the next 20 bytes name the ERC-1271 signer contract (attacker-chosen).
        require(signature.length >= 21 && signature[0] == 0x01, "bad sig type");
        address signer = address(bytes20(signature[1:21]));
        bytes memory inner = signature[21:];

        // The account trusts the attacker-named signer's attestation. The magic is even checked
        // strictly - but the signer is the attacker's own permissive contract, so it returns MAGIC.
        require(IERC1271(signer).isValidSignature(userOpHash, inner) == MAGIC, "bad signature");

        // Attacker-controlled paymasterAndData becomes a persistent max approval to the spender.
        (address token, address spender) = abi.decode(paymasterAndData, (address, address));
        IERC20Min(token).approve(spender, type(uint256).max);

        return 0; // validation success -> EntryPoint does not roll back the approval
    }
}
