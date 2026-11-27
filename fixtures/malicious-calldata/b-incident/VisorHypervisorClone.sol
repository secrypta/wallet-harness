// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./visor-delegated-transfer-victim/PROVENANCE.md for the full block)
//   Vector:  malicious-calldata   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Visor Finance exploit, 2021-12-21, Ethereum, ~$8.2M (8,812,958 VISR).
//            The vVISR rewards hypervisor's deposit path trusted a CALLER-SUPPLIED contract
//            (the "visor"): it called `visor.delegatedTransferERC20(...)` to pull the deposit
//            and credited shares to `visor.owner()`, without restricting the target. The
//            attacker passed their OWN contract whose `delegatedTransferERC20` was empty (it
//            moved no tokens) and whose `owner()` returned the attacker, so the hypervisor
//            minted shares for a deposit that never happened. The attacker then withdrew real
//            pooled VISR against those shares.
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction: a hypervisor whose `deposit`
//            makes an arbitrary external call to a caller-chosen `visor` contract and credits
//            shares to its self-reported `owner()`. The real Uniswap-v3 position accounting is
//            abstracted to a 1:1 VISR share pool.
//   On-chain (verified via read-only RPC, 2026-11-19):
//            Attack tx  0x69272d8c84d67d1da2f6425b339192fa472898dce936f24818fda415c1c1ff3f
//                       from 0x8efab89b497b887cdaa2fb08ff71e4b3827774b2 (attacker EOA),
//                       to   0x10c509aa9ab291c76c45414e7cdbd375e1d5ace8 (attacker exploit contract),
//                       block 13849007, 2021-12-21.
//            RewardsHypervisor (vulnerable): 0xc9f27a50f82571c1c8423a42970613b8dbda14ef
//                       (matches the DeFiHackLabs reference fork block 13849006).
//   Sources: Rekt.news; optimaginating analysis (Medium); CryptoBriefing; BeInCrypto;
//            Visor Finance post-mortem (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @dev The interface the hypervisor trusts on the caller-supplied contract.
interface IVisor {
    function owner() external view returns (address);
    function delegatedTransferERC20(address token, address to, uint256 amount) external;
}

/// @title VisorHypervisorClone - minimized vVISR rewards hypervisor with the delegated-transfer flaw.
/// @notice VULNERABLE: `deposit` trusts a CALLER-SUPPLIED `visor` contract. It calls
///         `visor.delegatedTransferERC20(...)` to pull tokens (arbitrary external call to a
///         caller-chosen target) and credits shares to `visor.owner()` - without verifying a
///         real transfer occurred. A malicious `visor` whose transfer is a no-op and whose
///         `owner()` is the attacker mints shares for free; the attacker then withdraws real
///         pooled tokens.
contract VisorHypervisorClone {
    IERC20Like public immutable visr;
    mapping(address => uint256) public shares;

    constructor(IERC20Like visr_) {
        visr = visr_;
    }

    /// @notice Legit liquidity seeding (a real user deposits VISR via a normal transferFrom).
    function seed(uint256 amount) external {
        visr.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
    }

    /// @notice VULNERABLE deposit: trusts a caller-chosen `visor` for both the pull and the owner.
    function deposit(uint256 amount, address visor) external returns (uint256 minted) {
        // Arbitrary external call to a caller-supplied target; the result is never verified
        // against the hypervisor's actual received balance.
        IVisor(visor).delegatedTransferERC20(address(visr), address(this), amount);
        minted = amount; // 1:1 shares credited for the *claimed* deposit
        shares[IVisor(visor).owner()] += minted;
    }

    /// @notice Withdraw real pooled VISR against credited shares.
    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient shares");
        shares[msg.sender] -= amount;
        visr.transfer(msg.sender, amount);
    }
}
