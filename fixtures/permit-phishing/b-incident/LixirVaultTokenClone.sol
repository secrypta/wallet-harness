// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LixirVaultTokenClone - minimized offline clone of the broken-permit drain exploited
///        against Lixir vault tokens (incident 2026-06).
/// @notice NOT our toy: a faithful, minimized reproduction of the affected token's exploited
///         surface. Per the public post-mortem, Lixir vault-token `permit` "accepted a dummy
///         signature as long as ecrecover returned a nonzero address" - i.e. it checked only
///         that the recovered signer was non-zero, NOT that it equalled the owner. An attacker
///         forged a dummy signature, obtained an allowance, and `transferFrom`'d each holder's
///         full vault-token balance. Only that broken permit + allowance surface is modeled
///         here. Provenance (tx hash, addresses, source) in lixir-permit-victim/PROVENANCE.md.
///         Offline only - no network, no live RPC. Built/run in Docker.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
contract LixirVaultTokenClone {
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

    /// @notice THE BUG (as documented): the permit grants the allowance as long as `ecrecover`
    ///         returns a non-zero address. It never checks that the recovered signer equals
    ///         `owner`, so ANY dummy signature that recovers to some nonzero address is accepted.
    ///         A correct permit would `require(recovered == owner)` (cf. the solady-permit-safe
    ///         holdout, which does exactly that and rejects the forgery).
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
        require(recovered != address(0), "LVT: invalid signature"); // BUG: should be == owner
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
