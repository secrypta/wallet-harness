// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title Permit2SafeToken - minimal MIT ERC-20 vehicle for the real-Permit2 (c) fixture.
/// @notice A plain, standard ERC-20 with a test-only `mint`. It exists only to be the token
///         the victim approves to the REAL vendored Uniswap Permit2 and that Permit2 then
///         moves via its allowance logic. Kept at pragma >=0.8.0 so it shares Permit2's exact
///         0.8.17 compilation subgraph (the repo's MockERC20 is ^0.8.24 and cannot). Standard
///         semantics; an unlimited allowance is not decremented. Never deploy on a real net.
contract Permit2SafeToken {
    string public name = "Permit2 Safe Test Token";
    string public symbol = "P2S";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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
        require(allowed >= amount, "insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
