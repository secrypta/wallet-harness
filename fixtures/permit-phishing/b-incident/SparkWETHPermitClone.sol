// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SparkWETHPermitClone - minimized offline clone of an EIP-2612 permit token for the
///        permit-phishing (b) real-incident fixture (Spark WETH / spWETH drain, 2024-09-28).
/// @notice NOT our toy, and NOT third-party exploit code: a faithful, minimized reproduction of
///         the affected token's EIP-2612 `permit` surface, authored here (MIT). The drained asset
///         was Spark WETH (spWETH, 18 decimals), a Spark/Aave-v3-style aToken exposing EIP-2612
///         `permit` (selector 0xd505accf). The documented on-chain path (drain tx
///         0xf7c00f18...1c1d8fb, Ethereum block 20847274 = 0x13e1aaa): the victim signed one
///         off-chain phishing permit naming the attacker's drainer contract as `spender` with an
///         unbounded `value`; the drainer submitted `permit` to set the allowance, then swept the
///         victim's entire balance with TWO `transferFrom` calls that split the proceeds across
///         two recipient wallets - all in a single transaction.
///
///         Only the ERC-20 + EIP-2612 surface needed to replay that path is modeled. The EIP-712
///         domain is modeled to the Spark/Aave-v3 aToken convention (name + version "1"); the
///         reproduction does not depend on matching mainnet's exact domain separator - the
///         signature is produced and consumed within the offline test over this same domain.
///         Offline only - no network, no live RPC. Provenance (tx, addresses, block, amounts,
///         sources) in PROVENANCE.md.
contract SparkWETHPermitClone {
    string public name = "Spark WETH";
    string public symbol = "spWETH";
    uint8 public constant decimals = 18;

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
        // Spark/Aave-v3 aToken EIP-712 domain revision is "1".
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes("1")),
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

    /// @notice Standard EIP-2612 permit: a valid owner signature sets `spender`'s allowance.
    function permit(
        address owner, address spender, uint256 value, uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "spWETH: permit expired");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "spWETH: invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "spWETH: insufficient allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "spWETH: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
