// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Permit2 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title ToyPermit2 - minimal model of Uniswap Permit2 `AllowanceTransfer` (tier a/b toy).
/// @notice Faithful-mechanism toy of the shared Permit2 allowance contract
///         (`0x000000000022D473030F116dDEE9F6B43aC78BA3`): a user makes a one-time ERC-20
///         `approve(permit2, max)`, then grants per-spender pull rights via OFF-CHAIN
///         EIP-712 signatures over a `PermitSingle`/`PermitBatch` (no tx, no gas - which is
///         why it is phished). An attacker who collects a signed, unbounded permit submits
///         `permit(...)` then `transferFrom(...)` and pulls the balance in one tx. This is a
///         TOY (our own typehashes/storage) used by tiers (a) and (b); tier (c) runs the
///         REAL vendored Uniswap Permit2. MIT, no third-party source.
contract ToyPermit2 {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    struct PermitBatch {
        PermitDetails[] details;
        address spender;
        uint256 sigDeadline;
    }

    struct PackedAllowance {
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    // allowance[owner][token][spender]
    mapping(address => mapping(address => mapping(address => PackedAllowance))) public allowance;

    bytes32 public immutable DOMAIN_SEPARATOR;

    // Typehashes mirror the SHAPE of Permit2's (toy copy; the real contract is vendored in c).
    bytes32 private constant _PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 private constant _PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );
    bytes32 private constant _PERMIT_BATCH_TYPEHASH = keccak256(
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    error SignatureExpired();
    error AllowanceExpired();
    error InsufficientAllowance();
    error InvalidNonce();
    error BadSignature();

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("Permit2"),
                block.chainid,
                address(this)
            )
        );
    }

    function _hashDetails(PermitDetails calldata d) internal pure returns (bytes32) {
        return keccak256(abi.encode(_PERMIT_DETAILS_TYPEHASH, d.token, d.amount, d.expiration, d.nonce));
    }

    function _typedDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function _verify(address owner, bytes32 digest, bytes calldata sig) internal pure {
        if (sig.length != 65) revert BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != owner) revert BadSignature();
    }

    /// @notice AllowanceTransfer: set a single token allowance from the owner's signature.
    function permit(address owner, PermitSingle calldata single, bytes calldata sig) external {
        if (block.timestamp > single.sigDeadline) revert SignatureExpired();
        bytes32 structHash = keccak256(
            abi.encode(_PERMIT_SINGLE_TYPEHASH, _hashDetails(single.details), single.spender, single.sigDeadline)
        );
        _verify(owner, _typedDigest(structHash), sig);
        _updateAllowance(owner, single.details, single.spender);
    }

    /// @notice AllowanceTransfer: set MANY token allowances from ONE signature (the Permit2
    ///         feature the PEPE incident abused - one signature drained several tokens).
    function permitBatch(address owner, PermitBatch calldata batch, bytes calldata sig) external {
        if (block.timestamp > batch.sigDeadline) revert SignatureExpired();
        bytes32[] memory detailHashes = new bytes32[](batch.details.length);
        for (uint256 i = 0; i < batch.details.length; i++) {
            detailHashes[i] = _hashDetails(batch.details[i]);
        }
        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_BATCH_TYPEHASH, keccak256(abi.encodePacked(detailHashes)), batch.spender, batch.sigDeadline
            )
        );
        _verify(owner, _typedDigest(structHash), sig);
        for (uint256 i = 0; i < batch.details.length; i++) {
            _updateAllowance(owner, batch.details[i], batch.spender);
        }
    }

    function _updateAllowance(address owner, PermitDetails calldata d, address spender) internal {
        PackedAllowance storage a = allowance[owner][d.token][spender];
        if (a.nonce != d.nonce) revert InvalidNonce();
        a.amount = d.amount;
        a.expiration = d.expiration;
        a.nonce = d.nonce + 1;
    }

    /// @notice Pull tokens using a Permit2 allowance. `msg.sender` is the spender.
    ///         Requires the owner's one-time `approve(permit2, max)` on the token.
    function transferFrom(address from, address to, uint160 amount, address token) external {
        PackedAllowance storage a = allowance[from][token][msg.sender];
        if (block.timestamp > a.expiration) revert AllowanceExpired();
        if (a.amount < amount) revert InsufficientAllowance();
        if (a.amount != type(uint160).max) {
            a.amount -= amount;
        }
        require(IERC20Permit2(token).transferFrom(from, to, amount), "transfer failed");
    }
}
