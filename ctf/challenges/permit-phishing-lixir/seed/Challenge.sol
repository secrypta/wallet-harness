// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - minimized Lixir vault token with the real, broken EIP-2612 permit.
/// @notice This is the VULNERABLE version, reproducing the documented incident bug. Your job is
///         to fix `permit` so the forged-permit drain no longer works, WITHOUT breaking a
///         genuine owner-signed permit.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this name
///         and arguments. You may change only the body of `permit`.
///
/// THE BUG (as documented): `permit` grants the allowance as long as `ecrecover` returns a
/// non-zero address. It never checks that the recovered signer equals `owner`, so ANY dummy
/// signature that recovers to some nonzero address is accepted - a forged signature grants an
/// allowance the owner never authorized, and `transferFrom` then drains the holder.
contract Challenge {
    string public name = "Lixir Vault Token (minimized incident clone)";
    string public symbol = "LVT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "LVT: permit expired");
        bytes32 digest = keccak256(abi.encode(owner, spender, value, deadline, nonces[owner]++));
        address recovered = ecrecover(digest, v, r, s);
        // BUG: should be `recovered == owner`; accepting any nonzero signer lets a forged
        //      signature grant the allowance.
        require(recovered != address(0), "LVT: invalid signature");
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "LVT: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "LVT: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
        return true;
    }
}
