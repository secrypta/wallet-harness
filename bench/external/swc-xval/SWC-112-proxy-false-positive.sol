// SPDX-License-Identifier: MIT
//
// EXTERNAL CROSS-VALIDATION fixture - NOT part of the real-incident corpus.
// Source:   SWC Registry (SmartContractSecurity/SWC-registry, MIT),
//           entries/docs/SWC-112.md "Samples" -> proxy_pattern_false_positive.sol,
//           commit 1b6227074ecd180b374e4844153afdda0332f979 (retrieved 2026-11-14).
// SWC-112:  the registry's documented KNOWN-FALSE-POSITIVE pattern - a delegatecall to a
//           caller-supplied target that is REQUIRED to revert (`require(!_to.delegatecall(...))`),
//           so it cannot mutate the caller's storage. The registry flags this as a pattern a
//           naive delegatecall-detector would wrongly report.
// Nature:   SYNTHETIC example, PORTED to 0.8.x. External PRECISION cross-check (not a real
//           incident). A hit here is a real detector false positive (report, do not suppress);
//           silence is the ideal cross-validation outcome.
// Port diff (0.4.24 -> 0.8.24): added SPDX; `pragma ^0.8.24`; `bytes _data` ->
//           `bytes calldata _data`; delegatecall success captured and its negation required;
//           `msg.sender.transfer` -> `payable(msg.sender).transfer`. Logic unchanged.
pragma solidity ^0.8.24;

contract proxy {
    address owner;

    function proxyCall(address _to, bytes calldata _data) external {
        (bool ok,) = _to.delegatecall(_data);
        require(!ok);
    }

    function withdraw() external {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
