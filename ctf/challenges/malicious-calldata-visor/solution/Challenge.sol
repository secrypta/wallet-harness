// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IVisor {
    function owner() external view returns (address);
    function delegatedTransferERC20(address token, address to, uint256 amount) external;
}

/// @title Challenge - reference FIX for the Visor Finance delegated-transfer drain.
/// @notice Don't trust a self-report. Measure the hypervisor's VISR balance before and after
///         the pull and require it actually rose by `amount`, then credit the shares to the
///         caller (not the helper's self-reported `owner()`). A no-op transfer now mints
///         nothing, while a genuine deposit still credits withdrawable shares.
contract Challenge {
    IERC20Like public immutable visr;
    mapping(address => uint256) public shares;

    constructor(IERC20Like visr_) {
        visr = visr_;
    }

    function seed(uint256 amount) external {
        visr.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }

    function deposit(uint256 amount, address visor) external returns (uint256 minted) {
        // FIX: credit only VISR actually received, and only to the real depositor.
        uint256 before = visr.balanceOf(address(this));
        IVisor(visor).delegatedTransferERC20(address(visr), address(this), amount);
        uint256 received = visr.balanceOf(address(this)) - before;
        require(received == amount, "deposit: hypervisor did not receive the claimed amount");
        minted = received;
        shares[msg.sender] += minted;
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient shares");
        shares[msg.sender] -= amount;
        visr.transfer(msg.sender, amount);
    }
}
