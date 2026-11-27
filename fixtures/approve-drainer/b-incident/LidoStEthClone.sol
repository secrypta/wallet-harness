// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LidoStEthClone - minimized offline clone of the stETH allowance surface drained in
///        the 2023-09-06 whale approval-phishing incident, for the approve-drainer (b) fixture.
/// @notice NOT our toy: a faithful, minimized reproduction of the affected token's RELEVANT
///         surface. The drained asset was Lido staked ether (stETH), an 18-decimal ERC-20 that
///         exposes the OpenZeppelin-style allowance API including `increaseAllowance`. The
///         documented attack path was: the victim was phished into calling
///         `increaseAllowance(attacker, ...)` (an on-chain approval, NOT an off-chain permit),
///         then the attacker `transferFrom`'d the victim's whole stETH balance out. Only the
///         allowance + transferFrom surface needed to replay that path is modeled here; stETH's
///         share/rebase accounting is omitted (irrelevant to the approve-drain path).
///         Provenance (tx hash, addresses, sources) in steth-whale-victim/PROVENANCE.md.
///         Offline only - no network, no live RPC. Build/run in Docker.
contract LidoStEthClone {
    string public name = "Liquid staked Ether 2.0 (minimized incident clone)";
    string public symbol = "stETH";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// @dev Test-only mint to fund the example victim for the offline replay.
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

    /// @notice OpenZeppelin-style allowance bump - the exact call the victim was phished into
    ///         signing (the documented "increaseAllowance" approval step).
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        uint256 updated = allowance[msg.sender][spender] + addedValue;
        allowance[msg.sender][spender] = updated;
        emit Approval(msg.sender, spender, updated);
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
