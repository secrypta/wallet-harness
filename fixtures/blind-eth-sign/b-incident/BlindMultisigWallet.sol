// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BlindMultisigWallet - minimized Safe-like multisig that executes an operation
///        authorized by owner signatures over an OPAQUE transaction digest, for the
///        blind-eth-sign (b) real-incident fixture (Bybit / Safe, 2025-02-21).
/// @notice This models the signing defect behind the Bybit theft: the multisig owners
///         approved a transaction digest their hardware wallets could not decode (blind
///         signing), and that authorization executed an operation that drained the wallet.
///         The real on-chain operation (tx 0x46deef...7882, Safe execTransaction selector
///         0x6a761202) used a DELEGATECALL that overwrote the Safe singleton (masterCopy,
///         storage slot 0) with a malicious implementation (0xbDd077...9516) exposing
///         sweepETH/sweepERC20. We reproduce the blind-signed-authorization -> drain ESSENCE
///         (the signing surface this vector is about), not the delegatecall/upgrade mechanics
///         (which other detector rules cover). The owners sign `txHash` without decoding
///         (to, value, data); because it is opaque, they authorize a transfer of the wallet's
///         balance to the attacker. A clear-signing wallet would decode and display the
///         operation and the owners would refuse. Offline only - no live RPC. See PROVENANCE.md.
contract BlindMultisigWallet {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public immutable threshold;
    uint256 public nonce;

    event ExecutionSuccess(bytes32 indexed txHash);

    constructor(address[] memory _owners, uint256 _threshold) {
        require(_threshold > 0 && _threshold <= _owners.length, "bad threshold");
        for (uint256 i = 0; i < _owners.length; i++) {
            address o = _owners[i];
            require(o != address(0) && !isOwner[o], "bad owner");
            isOwner[o] = true;
            owners.push(o);
        }
        threshold = _threshold;
    }

    receive() external payable {}

    /// @notice The digest the owners are asked to sign. It commits to the operation
    ///         (to, value, data) and the nonce, but a hardware wallet that cannot decode the
    ///         payload shows the signer only this opaque 32-byte value - the blind-signing
    ///         condition this vector is about.
    function getTransactionHash(address to, uint256 value, bytes calldata data, uint256 _nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(address(this), to, value, keccak256(data), _nonce));
    }

    /// @notice Executes `(to, value, data)` once `threshold` distinct owners have signed the
    ///         transaction hash. Signatures are the concatenation of 65-byte (r,s,v) tuples,
    ///         sorted ascending by signer address (as Safe requires). No decoding of the
    ///         operation is performed or displayed on-chain: authority comes purely from the
    ///         signatures over the opaque hash.
    function execTransaction(address to, uint256 value, bytes calldata data, bytes calldata signatures)
        external
        returns (bool success)
    {
        bytes32 txHash = getTransactionHash(to, value, data, nonce);
        require(signatures.length >= threshold * 65, "not enough signatures");

        address lastSigner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signatures, i);
            address signer = ecrecover(txHash, v, r, s);
            require(signer != address(0) && isOwner[signer], "invalid signer");
            require(signer > lastSigner, "signers not sorted/unique");
            lastSigner = signer;
        }

        nonce++;
        (success,) = to.call{value: value}(data);
        require(success, "exec failed");
        emit ExecutionSuccess(txHash);
    }

    function _splitSignature(bytes calldata sigs, uint256 i)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        uint256 off = i * 65;
        r = bytes32(sigs[off:off + 32]);
        s = bytes32(sigs[off + 32:off + 64]);
        v = uint8(sigs[off + 64]);
    }
}
