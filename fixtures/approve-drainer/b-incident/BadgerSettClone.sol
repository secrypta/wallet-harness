// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BadgerSettClone - minimized offline clone of the ERC-20 drained in the BadgerDAO
///        incident (2021-12-02), for the approve-drainer (b) real-incident fixture.
/// @notice NOT our toy: this is a faithful, minimized reproduction of the affected token's
///         relevant surface. The drained asset was a Badger Sett / Yearn-style vault ERC-20
///         (byvWBTC, 8 decimals) implementing the OpenZeppelin-style allowance API,
///         including `increaseAllowance`. The documented attack path was: a compromised
///         front-end induced victims to call `increaseAllowance(attacker, ...)`, then the
///         attacker `transferFrom`'d the victims' balances out. Only the allowance +
///         transferFrom surface needed to replay that path is modeled here; all vault
///         accounting is omitted. Provenance (tx hashes, addresses, source) in PROVENANCE.md.
///         Offline only - no network, no live RPC. Build/run in Docker.
contract BadgerSettClone {
    string public name = "Badger Sett byvWBTC (minimized incident clone)";
    string public symbol = "byvWBTC";
    uint8 public constant decimals = 8; // WBTC-based vault token

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

    /// @notice OpenZeppelin-style allowance bump - the exact call the compromised Badger
    ///         front-end injected into victim wallets.
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
