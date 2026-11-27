// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title StEthLikeToken - minimized stETH-like ERC-20 (the victim's REAL asset) for the
///        fake-airdrop (b) real-incident fixture (LFG fake-airdrop guide, 2023).
/// @notice NOT the bait: this is the genuine, valuable asset the victim actually held. The
///         LFG fake-airdrop "claim" flow induced the victim to approve the attacker's
///         spender on this real asset, which was then drained via transferFrom. Only the
///         standard ERC-20 approve/transferFrom surface needed to replay that path is
///         modeled (18 decimals, as stETH). Offline only - no live RPC. See PROVENANCE.md.
contract StEthLikeToken {
    string public name = "Liquid staked Ether 2.0";
    string public symbol = "stETH";
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
        require(allowed >= amount, "stETH: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "stETH: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
