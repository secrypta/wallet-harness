// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the delegatecall-hijack vector.
//
// The safety-relevant machinery is UNMODIFIED Solady v0.1.22:
//   source : github.com/Vectorized/solady (tag v0.1.22, commit 65e87c72)
//   license: MIT (see ../../../vendor/solady/LICENSE and ../../../vendor/PROVENANCE.md)
// Solady `ERC7821` is a canonical ERC-7821 batch-execution account. Its executor runs each
// batched operation with a plain `call` (see ERC7821._execute(address,uint256,bytes,bytes32):
// `call(gas(), to, value, ...)`), NOT a delegatecall - there is no `operation` flag to flip to
// delegatecall. So the delegatecall-hijack vector (the Bybit/Parity pattern: an owner-approved
// transaction whose `operation` is delegatecall runs attacker code in the wallet's own storage
// and rewrites its implementation/owner) is structurally absent: foreign code invoked through
// this wallet always runs in the callee's own context, never the wallet's.
//
// The only code authored here on top of the unmodified Solady base is this thin wallet: a
// stored `owner` and an `_execute` override that authorizes the owner. The execution primitive
// itself - the plain `call` that makes the hijack impossible - is Solady's unmodified code.

import {ERC7821} from "../../../vendor/solady-accounts/accounts/ERC7821.sol";

/// @title SoladyERC7821Wallet - an ERC-7821 batch wallet over the unmodified Solady executor.
contract SoladyERC7821Wallet is ERC7821 {
    address public owner; // slot 0

    constructor(address owner_) {
        owner = owner_;
    }

    /// @dev Authorize the owner to drive `execute`. Execution still uses Solady's unmodified
    ///      `_execute(calls)` -> plain `call`, so no delegatecall-hijack surface is introduced.
    function _execute(bytes32, bytes calldata, Call[] calldata calls, bytes calldata)
        internal
        override
    {
        require(msg.sender == owner || msg.sender == address(this), "ERC7821: not authorized");
        _execute(calls, bytes32(0));
    }
}
