// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimized OFFLINE reproduction of the Bebop JamSettlement drain (Arbitrum, 2025-08-12, ~$21K).
// Authored in THIS repo (MIT). NOT a copy of the on-chain Bebop contract nor of any third-party
// PoC. The documented MECHANISM is reproduced; see ./bebop-jam-settlement-victim/PROVENANCE.md for
// the incident facts (attacker, vulnerable contract, tx hash, sources) and the DeFiHackLabs
// reference used to locate them.
//
// Root cause: the settlement executed caller-supplied `interactions` (arbitrary external calls)
// without a signature that authenticated those fund movements. An attacker submitted a self-taken
// order with an EMPTY signature and interactions of the form `transferFrom(victim, attacker, amount)`;
// the settlement ran them against third parties' standing allowances to the settlement contract.
// The signature gate did not bind the signer to the tokens the interactions moved.

/// @dev Minimal ERC-20 (approve / transferFrom) - the standing-allowance sink the drain abuses.
contract MiniToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

struct Order {
    address taker; // who the settlement treats as the order's authorizer
    address receiver;
    uint256 nonce;
}

struct Interaction {
    address to; // arbitrary call target
    bytes data; // arbitrary calldata (here: transferFrom of a victim's approved balance)
}

/// @notice Minimized vulnerable settlement. THE FLAW: `settle` authenticates only `order.taker`
///         (and accepts an EMPTY signature when the taker is the caller), yet the interactions it
///         executes can move ANY token that ANY address has approved to the settlement. The
///         signature is never bound to the fund movements the interactions perform.
contract JamSettlementClone {
    function settle(Order calldata order, bytes calldata signature, Interaction[] calldata interactions)
        external
    {
        // Signature "validation": a self-taken order needs no real signature. (In the real incident
        // an empty signature was accepted.) Crucially, nothing here binds the authorizer to the
        // tokens the interactions below move.
        if (order.taker != msg.sender) {
            require(signature.length != 0, "missing signature");
            // (a real signature would still only prove the taker signed SOMETHING, not these pulls)
        }

        // Execute arbitrary caller-supplied interactions from the settlement's own context, which is
        // the approved spender for every integrating user.
        for (uint256 i; i < interactions.length; ++i) {
            (bool ok,) = interactions[i].to.call(interactions[i].data);
            require(ok, "interaction failed");
        }
    }
}
