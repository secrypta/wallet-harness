// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Challenge - a payments wallet that executes a token operation.
/// @notice This is the VULNERABLE version. Your job is to fix `execute` so the
///         malicious-calldata vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep the function signature exactly as-is - the hidden grader calls it by this
///         name and arguments. You may change only the body.
///
/// The intended use: pay the fixed `merchant` up to `maxPayment` of `token`, by executing a
/// `transfer(merchant, amount)` calldata against the token. The bug below is that `execute`
/// runs WHATEVER calldata it is handed, by its presented label, without decoding the real
/// effect - so calldata that is really `transfer(attacker, entireBalance)` drains the wallet.
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
        // BUG: the calldata is executed as-is, trusting its presented intent. Its real effect
        // (recipient, amount, even which contract) is never checked.
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "execute: call failed");
        return ret;
    }
}
