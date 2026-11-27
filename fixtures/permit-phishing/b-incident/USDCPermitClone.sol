// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title USDCPermitClone - minimized offline clone of an EIP-2612 permit token for the
///        permit-phishing (b) real-incident fixture (USDC drain, 2026-03-16).
/// @notice NOT our toy: a faithful, minimized reproduction of the affected token's permit
///         surface. The drained asset was USDC (6 decimals) exposing EIP-2612
///         `permit` (selector 0xd505accf). The documented path: the victim signed an
///         off-chain permit with value = MAX_UINT256 and an effectively-never deadline, the
///         attacker's spender contract submitted `permit` to set the allowance, then
///         `transferFrom`'d the balance out - all in one tx. Only the ERC-20 + EIP-2612
///         surface needed to replay that path is modeled here (name/version match USDC's
///         EIP-712 domain for fidelity). Offline only - no network, no live RPC.
///         Provenance (tx, addresses, block) in PROVENANCE.md.
contract USDCPermitClone {
    string public name = "USD Coin";
    string public symbol = "USDC";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    mapping(address => uint256) public nonces;
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        // USDC's EIP-712 domain uses version "2".
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes("2")),
            block.chainid,
            address(this)
        ));
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "USDC: permit expired");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "USDC: bad signature");
        nonces[owner]++;
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "USDC: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "USDC: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
        return true;
    }
}
