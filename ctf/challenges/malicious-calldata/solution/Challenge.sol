// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ⚠️ SPOILER - reference solution. Do not read this before attempting the challenge.

/// @title Challenge - reference FIX for the malicious-calldata vector.
/// @notice Don't trust the presented intent - decode the calldata's REAL effect and enforce
///         that it matches the one sanctioned action: a `transfer(merchant, amount)` on the
///         known token, with `amount <= maxPayment`. Anything else (another recipient, a
///         larger amount, a different selector or target) is rejected. The legitimate
///         merchant payment still goes through.
contract Challenge {
    address public immutable token;
    address public immutable merchant;
    uint256 public immutable maxPayment;

    constructor(address token_, address merchant_, uint256 maxPayment_) {
        token = token_;
        merchant = merchant_;
        maxPayment = maxPayment_;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        // FIX: decode and validate the real effect before executing it.
        require(target == token, "execute: target not the sanctioned token");
        require(data.length == 4 + 32 + 32, "execute: unexpected calldata shape");
        require(bytes4(data[0:4]) == bytes4(keccak256("transfer(address,uint256)")), "execute: not a transfer");
        (address to, uint256 amount) = abi.decode(data[4:], (address, uint256));
        require(to == merchant, "execute: recipient is not the sanctioned merchant");
        require(amount <= maxPayment, "execute: amount exceeds the sanctioned limit");

        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "execute: call failed");
        return ret;
    }
}
