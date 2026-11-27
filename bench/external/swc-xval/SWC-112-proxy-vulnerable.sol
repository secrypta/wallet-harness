// SPDX-License-Identifier: MIT
//
// EXTERNAL CROSS-VALIDATION fixture - NOT part of the real-incident corpus.
// Source:   SWC Registry (SmartContractSecurity/SWC-registry, MIT),
//           entries/docs/SWC-112.md "Samples" -> proxy.sol,
//           commit 1b6227074ecd180b374e4844153afdda0332f979 (retrieved 2026-11-14).
// SWC-112:  "Delegatecall to Untrusted Callee" (Relationships: CWE-829).
// Nature:   SYNTHETIC example authored by the SWC Registry, PORTED to 0.8.x (the original
//           pins ^0.4.24). External cross-validation of an INDEPENDENT taxonomy, NOT a real
//           incident. Expected: our scanner rule R7 (delegatecall-hijack) MUST flag this.
// Port diff (0.4.24 -> 0.8.24): added SPDX; `pragma ^0.8.24`; removed `public` from the
//           constructor; `bytes _data` -> `bytes calldata _data`; delegatecall now returns
//           (bool,bytes) so its success is captured and required. The vulnerable primitive -
//           a delegatecall whose target is a caller-supplied argument - is unchanged.
pragma solidity ^0.8.24;

contract Proxy {
    address owner;

    constructor() {
        owner = msg.sender;
    }

    function forward(address callee, bytes calldata _data) public {
        (bool ok,) = callee.delegatecall(_data);
        require(ok);
    }
}
