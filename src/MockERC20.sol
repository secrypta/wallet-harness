// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MockERC20 - minimal ERC-20 (+ EIP-2612 permit) used by the corpus vectors.
/// @notice Toy token for test scenarios only. Open `mint` is intentional so tests
///         can fund wallets with one call; never use this on a real network.
///         Classic ERC-20 semantics: an unlimited allowance (type(uint256).max)
///         is NOT decremented on transferFrom, so a single unlimited approve grants
///         a spender permanent access to the full balance - that is the vector.
contract MockERC20 {
    string public name = "Mock Test Token";
    string public symbol = "MTT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // --- EIP-2612 permit (used by the permit-phishing corpus vector) ---
    // permit sets an allowance from an OFF-CHAIN owner signature: no tx, no gas from the
    // owner, "nothing to inspect in the wallet". That is exactly why it is phished.
    mapping(address => uint256) public nonces;
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        // EIP-712 domain. `name` is set in its field initializer above; version "1".
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    /// @notice EIP-2612: set allowance from the owner's signature. Guards are strict so a
    ///         "blocked" result in tests is never due to a malformed signature:
    ///         deadline must be in the future; a zeroed/forged signature makes ecrecover
    ///         return address(0); the recovered signer must equal `owner`; the nonce is
    ///         consumed only after the checks pass.
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "ERC20: permit expired");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "ERC20: bad signature");
        nonces[owner]++;
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
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

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ERC20: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
