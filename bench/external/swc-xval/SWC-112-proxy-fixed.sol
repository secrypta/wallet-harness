// SPDX-License-Identifier: MIT
//
// EXTERNAL CROSS-VALIDATION fixture - NOT part of the real-incident corpus.
// Source:   SWC Registry (SmartContractSecurity/SWC-registry, MIT),
//           entries/docs/SWC-112.md "Samples" -> proxy_fixed.sol,
//           commit 1b6227074ecd180b374e4844153afdda0332f979 (retrieved 2026-11-14).
// SWC-112:  the registry's SAFE counterpart - the delegatecall target is an owner-only
//           stored variable, not a caller-supplied argument.
// Nature:   SYNTHETIC example, PORTED to 0.8.x. External PRECISION cross-check (not a real
//           incident). Expected: our scanner rule R7 MUST stay silent (target is not
//           caller-settable; only onlyOwner can set it).
// Port diff (0.4.24 -> 0.8.24): added SPDX; `pragma ^0.8.24`; removed `public` from the
//           constructor; `bytes _data` -> `bytes calldata _data`; delegatecall success
//           captured/required. Access-control logic unchanged.
pragma solidity ^0.8.24;

contract Proxy {
    address callee;
    address owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    constructor() {
        callee = address(0x0);
        owner = msg.sender;
    }

    function setCallee(address newCallee) public onlyOwner {
        callee = newCallee;
    }

    function forward(bytes calldata _data) public {
        (bool ok,) = callee.delegatecall(_data);
        require(ok);
    }
}
