// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FwDethPermitClone - minimized offline clone of an EIP-2612 permit token for the
///        permit-phishing (b) real-incident fixture (Few Wrapped Duo ETH / fwDETH drain on Blast,
///        2024-10-11).
/// @notice NOT our toy, and NOT third-party exploit code: a faithful, minimized reproduction of
///         the affected token's EIP-2612 `permit` surface, authored here (MIT). The drained asset
///         was fwDETH (Few Wrapped Duo ETH, 18 decimals) on the Blast network (chainid 81457), a
///         Duo-protocol wrapped ETH derivative exposing EIP-2612 `permit`.
///
///         MECHANISM-LEVEL reproduction (see PROVENANCE.md): the documented path is an offline
///         EIP-2612 `permit` phishing signature followed by `transferFrom`. Per BlockSec, "the
///         attacker lured the victim into signing a permit message offline and then used the
///         signed permit message to drain the fwDETH token from the victim's account." The drain
///         is reported in two stages (12,817.15 + 2,261.85 fwDETH = 15,079 total). There is NO
///         public drain-transaction hash and the official Blast explorer (blastscan.io) has been
///         deprecated, so this fixture is modeled at the MECHANISM level (as with the corpus's
///         beanstalk/furucombo/li-fi/socket tier-b cases) - amounts/date/network/mechanism from
///         multiple authorities, no fabricated tx or full addresses.
///
///         Only the ERC-20 + EIP-2612 surface needed to replay the path is modeled. The EIP-712
///         domain is modeled with the token's name + version "1"; the reproduction does not depend
///         on matching the real on-chain domain separator - the signature is produced and consumed
///         within the offline test over this same domain. Offline only - no network, no live RPC.
contract FwDethPermitClone {
    string public name = "Few Wrapped Duo ETH";
    string public symbol = "fwDETH";
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
        require(block.timestamp <= deadline, "fwDETH: permit expired");
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "fwDETH: invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "fwDETH: insufficient allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "fwDETH: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
