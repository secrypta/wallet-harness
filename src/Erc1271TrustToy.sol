// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// R15 toy pair: ERC-1271 forged / permissive signer trust (contract-signature drain).
//
// A signature-gated wallet authorizes a withdrawal by asking a signer *contract* "is this
// signature valid?" via EIP-1271 `isValidSignature` (magic 0x1626ba7e). The question R15 asks:
// can an attacker manufacture that "yes"? Two independent ways this goes wrong are shown as the
// two vuln contracts; the safe contract closes both.
//
//   PermissiveSignerWallet (vuln, axis i) - the signer address is a CALL PARAMETER: the caller
//       names which contract attests to their signature. An attacker passes their own contract,
//       which returns the magic for anything -> drain. (The real Lumi/Sodium 2026 shape.)
//   LooseResultWallet      (vuln, axis ii) - the signer is fixed, but the wallet trusts the bare
//       success of a low-level `staticcall` and never checks the returned value equals the magic,
//       so a signer that merely does-not-revert is accepted. (The Gnosis-Pay class.)
//   StrictSignerWallet     (safe)          - an IMMUTABLE signer AND a strict `== MAGIC` check.
//
// Toy only, never deployed.

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

/// @dev vuln (axis i): the trusted signer is a caller-supplied parameter. Note it even checks
///      the magic strictly - that does not help, because the attacker chose the signer.
contract PermissiveSignerWallet {
    bytes4 private constant MAGIC = 0x1626ba7e;

    function withdraw(
        address token,
        address to,
        uint256 amount,
        address signer,          // <-- caller names the ERC-1271 signer contract
        bytes calldata signature
    ) external {
        bytes32 digest = keccak256(abi.encode(token, to, amount));
        require(IERC1271(signer).isValidSignature(digest, signature) == MAGIC, "bad sig");
        require(IERC20Min(token).transfer(to, amount), "transfer failed");
    }
}

/// @dev vuln (axis ii): fixed signer, but authorizes on bare staticcall success - the returned
///      magic value is never checked, so any non-reverting signer passes.
contract LooseResultWallet {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function withdraw(address token, address to, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(token, to, amount));
        (bool ok, ) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, signature)
        );
        require(ok, "call failed"); // trusts success, not the magic value
        require(IERC20Min(token).transfer(to, amount), "transfer failed");
    }
}

/// @dev safe: immutable signer AND strict magic-value check -> R15 silent.
contract StrictSignerWallet {
    bytes4 private constant MAGIC = 0x1626ba7e;
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function withdraw(address token, address to, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(token, to, amount));
        bytes4 magic = IERC1271(signer).isValidSignature(digest, signature);
        require(magic == MAGIC, "bad sig");
        require(IERC20Min(token).transfer(to, amount), "transfer failed");
    }
}
