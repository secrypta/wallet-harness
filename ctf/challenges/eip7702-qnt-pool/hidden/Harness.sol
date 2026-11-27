// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test doubles for the eip7702-qnt-pool gate. No imports from the corpus /
// fixtures / vendor - the CTF is decoupled from the harness core by code. These model the
// incident's two supporting contracts: the reserve token and a pool that trusts its admin by
// address.

/// @dev Minimal ERC-20 stand-in for the pooled reserve token (QNT in the incident).
contract MockReserveToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev The reserve pool. It trusts its admin BY ADDRESS: `forwardTransaction` only checks that
///      the caller is the registered admin. In the incident the admin is the 7702-delegated
///      account, so whatever that account's executor calls is honored. This contract is correct
///      on its own terms - the fixable defect is in the executor (src/Challenge.sol), not here.
contract QntReservePool {
    address public admin;
    MockReserveToken public token;

    constructor(address admin_, MockReserveToken token_) {
        admin = admin_;
        token = token_;
    }

    function forwardTransaction(address to, uint256 amount) external {
        require(msg.sender == admin, "pool: not admin");
        token.transfer(to, amount);
    }
}
