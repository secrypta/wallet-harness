// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained test double for the Parity delegatecall-hijack gate. Kept out of the
// player's work copy until `solve` runs, so the exploit stays hidden.

/// @dev The per-user wallet proxy. Holds the ETH and forwards unknown calls to the shared
///      library (the Challenge) via delegatecall, so library code mutates THIS contract's
///      storage. `owner` is slot 0 and `initialized` is slot 1, aligned with the library.
contract ParityWalletProxy {
    address public owner;        // slot 0 (aligned with the library)
    bool public initialized;     // slot 1 (aligned with the library)
    address public immutable lib; // immutable: lives in code, no storage slot to clobber

    constructor(address lib_) {
        lib = lib_;
    }

    receive() external payable {}

    fallback() external payable {
        (bool ok, ) = lib.delegatecall(msg.data);
        require(ok, "proxy: delegatecall failed");
    }
}
