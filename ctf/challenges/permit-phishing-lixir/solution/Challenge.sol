// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the Lixir forged-permit drain.
/// @notice The only change is in `permit`: require that the recovered signer equals `owner`.
///         A genuine owner-signed permit still sets the allowance; a forged signature that
///         recovers to anyone other than `owner` is rejected, so no allowance is granted.
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
        // FIX: the recovered signer must be the owner - a forged non-owner signature is rejected.
        require(recovered != address(0) && recovered == owner, "LVT: invalid signature");
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
