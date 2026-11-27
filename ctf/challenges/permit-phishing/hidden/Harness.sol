// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the permit-phishing gate. Kept out of the player's work
// copy until `solve` runs, so the exploit stays hidden. These are minimal toys - never
// deploy them to a real network.

/// @dev Minimal ERC-20 with a real EIP-2612 `permit`: an allowance set from an off-chain
///      owner signature. The guards are strict so a blocked drain is never a side effect of
///      a malformed signature - the deadline must be in the future and the recovered signer
///      must equal `owner`.
contract MockERC20Permit {
    string public name = "Mock";
    string public symbol = "MOCK";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public immutable DOMAIN_SEPARATOR;

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
        balanceOf[to] += amount;
    }

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

/// @dev A spender the owner's permit authorizes. Used both as the legitimate puller (pulls
///      the agreed amount) and as the attacker (tries to pull the full balance).
contract Spender {
    function pull(address token, address owner, uint256 amount) external {
        MockERC20Permit(token).transferFrom(owner, address(this), amount);
    }
}
