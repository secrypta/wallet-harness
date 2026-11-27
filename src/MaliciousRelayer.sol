// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Settlement} from "./Settlement.sol";

/// @title MaliciousRelayer - submits a victim-signed order to drain the signer.
/// @notice The signature-phishing attacker never needs the victim to send a transaction:
///         holding the victim's signed order, the relayer submits it to the settlement and
///         the assets move. It can only move what the signed order authorized - an order
///         for the full balance to the attacker drains everything; a scoped order does not,
///         and an order the victim never signed reverts on the signature check.
contract MaliciousRelayer {
    /// @notice Relay a signed order to the settlement contract.
    function relay(Settlement settlement, Settlement.Order calldata order, uint8 v, bytes32 r, bytes32 s)
        external
    {
        settlement.settle(order, v, r, s);
    }
}
