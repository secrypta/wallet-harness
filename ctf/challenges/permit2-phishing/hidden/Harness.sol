// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the permit2-phishing gate. Kept out of the player's work
// copy until `solve` runs. These are minimal toys modelling Uniswap Permit2's
// AllowanceTransfer flow - NOT the real Permit2 contract - never deploy them.

/// @dev Minimal ERC-20. The owner does the one-time `approve(Permit2, max)` so Permit2 can
///      move tokens on its behalf.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "ERC20: insufficient allowance");
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev Minimal model of Permit2's AllowanceTransfer: one shared contract that holds
///      per-(owner,token,spender) allowances granted by an off-chain signature, and moves
///      tokens on the owner's behalf. The signature check is a real EIP-712 recover so a
///      blocked drain is never a side effect of a bad signature.
contract MockPermit2 {
    struct Allowance {
        uint160 amount;
        uint48 expiration;
    }
    // A single allowance authorization, signed off-chain (mirrors Permit2's PermitSingle).
    struct PermitSingle {
        address token;
        address spender;
        uint160 amount;
        uint48 expiration;
        uint256 nonce;
        uint256 sigDeadline;
    }
    // owner => token => spender => allowance
    mapping(address => mapping(address => mapping(address => Allowance))) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "PermitSingle(address token,address spender,uint160 amount,uint48 expiration,uint256 nonce,uint256 sigDeadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Permit2")),
            block.chainid,
            address(this)
        ));
    }

    function permit(address owner, PermitSingle calldata p, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= p.sigDeadline, "Permit2: signature expired");
        require(p.nonce == nonces[owner], "Permit2: bad nonce");
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, p.token, p.spender, p.amount, p.expiration, p.nonce, p.sigDeadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "Permit2: bad signature");
        nonces[owner]++;
        allowance[owner][p.token][p.spender] = Allowance(p.amount, p.expiration);
    }

    /// @notice Spender pulls `amount` of `token` from `owner`, bounded by the signed Permit2
    ///         allowance. Permit2 itself must hold a token allowance from `owner`.
    function transferFrom(address owner, address to, uint160 amount, address token) external {
        Allowance storage a = allowance[owner][token][msg.sender];
        require(block.timestamp <= a.expiration, "Permit2: allowance expired");
        require(a.amount >= amount, "Permit2: insufficient allowance");
        if (a.amount != type(uint160).max) {
            a.amount -= amount;
        }
        MockERC20(token).transferFrom(owner, to, amount);
    }
}

/// @dev A spender the owner's Permit2 signature authorizes. Legitimate puller and attacker.
contract Spender {
    function pull(address permit2, address token, address owner, uint160 amount) external {
        MockPermit2(permit2).transferFrom(owner, address(this), amount, token);
    }
}
