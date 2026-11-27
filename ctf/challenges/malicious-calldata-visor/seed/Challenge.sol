// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @dev The interface the hypervisor trusts on the caller-supplied `visor` contract.
interface IVisor {
    function owner() external view returns (address);
    function delegatedTransferERC20(address token, address to, uint256 amount) external;
}

/// @title Challenge - minimized vVISR rewards hypervisor with the delegated-transfer flaw.
/// @notice This is the VULNERABLE version. Your job is to fix `deposit` so the fake-credit
///         drain (Visor Finance, 2021-12-21) can no longer mint free shares, WITHOUT breaking
///         genuine deposits.
///
///         Keep the `deposit` signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only its body. (`seed`/`withdraw` are not part
///         of the puzzle.)
///
///         The bug: `deposit` trusts a CALLER-SUPPLIED `visor` contract - it calls
///         `visor.delegatedTransferERC20(...)` to pull the deposit and credits shares to
///         `visor.owner()`, never checking that the hypervisor actually received tokens. A
///         malicious `visor` whose transfer is a no-op and whose `owner()` is the attacker
///         mints shares for free; the attacker then withdraws real pooled VISR.
contract Challenge {
    IERC20Like public immutable visr;
    mapping(address => uint256) public shares;

    constructor(IERC20Like visr_) {
        visr = visr_;
    }

    /// @notice Legitimate liquidity seeding (a real user deposits VISR via a normal transferFrom).
    ///         Not part of the puzzle.
    function seed(uint256 amount) external {
        visr.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }

    function deposit(uint256 amount, address visor) external returns (uint256 minted) {
        // BUG: trusts a caller-chosen `visor` for both the pull and the credited owner, and
        // never verifies the hypervisor actually received `amount`.
        IVisor(visor).delegatedTransferERC20(address(visr), address(this), amount);
        minted = amount;                       // credits the *claimed* deposit
        shares[IVisor(visor).owner()] += minted; // ...to a self-reported owner
    }

    /// @notice Redeem shares for real pooled VISR. Not part of the puzzle.
    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient shares");
        shares[msg.sender] -= amount;
        visr.transfer(msg.sender, amount);
    }
}
