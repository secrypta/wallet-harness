// SPDX-License-Identifier: CC-BY-4.0
//
// External cross-validation fixture - NOT part of the drain-bench real-incident corpus.
//
// Provenance:
//   upstream corpus : smartbugs/smartbugs-curated  (repo code Apache-2.0)
//                     commit 230e649123477eff332742a59a1c7cc6dc286cab (retrieved 2026-11-14)
//                     path   dataset/access_control/FibonacciBalance.sol
//   original source : https://github.com/sigp/solidity-security-blog  (Adrian Manning)
//   original license: CC-BY-4.0  (verified at sigp/solidity-security-blog LICENSE, 2026-11-14)
//   upstream GT      : category=access_control, vulnerable_at_lines={31,38}
//
// PORTED from the original pragma ^0.4.22 to ^0.8.17 to compile under our pinned solc.
// This file is therefore NOT byte-identical to upstream. Value = taxonomy-agreement
// (does our scanner's view of the delegatecall surface agree with an independent GT?),
// NOT a real-incident reproduction.
//
// Port changes (faithful to the vulnerability):
//   - sha3(...)            -> keccak256(...)
//   - low-level .delegatecall(sig, arg) -> .delegatecall(abi.encodeWithSelector(sig, arg))
//     and returns (bool,bytes) tuple (0.5+ ABI), require(ok)
//   - unnamed fallback `function() public` -> `fallback() external`
//   - msg.sender.transfer -> payable(msg.sender).transfer
// The bug is preserved: a delegatecall into a library whose storage layout collides with
// the caller, driven by attacker-controlled calldata through the fallback.
pragma solidity ^0.8.17;

contract FibonacciBalance {

    address public fibonacciLibrary;
    uint public calculatedFibNumber;
    uint public start = 3;
    uint public withdrawalCounter;
    bytes4 constant fibSig = bytes4(keccak256("setFibonacci(uint256)"));

    constructor(address _fibonacciLibrary) payable {
        fibonacciLibrary = _fibonacciLibrary;
    }

    function withdraw() external {
        withdrawalCounter += 1;
        // delegatecall into a fixed library, selector fixed
        (bool ok, ) = fibonacciLibrary.delegatecall(abi.encodeWithSelector(fibSig, withdrawalCounter));
        require(ok);
        payable(msg.sender).transfer(calculatedFibNumber * 1 ether);
    }

    // attacker-controlled calldata is forwarded verbatim into the library (storage collision)
    fallback() external {
        (bool ok, ) = fibonacciLibrary.delegatecall(msg.data);
        require(ok);
    }
}

contract FibonacciLib {
    uint public start;
    uint public calculatedFibNumber;

    function setStart(uint _start) public {
        start = _start;
    }

    function setFibonacci(uint n) public {
        calculatedFibNumber = fibonacci(n);
    }

    function fibonacci(uint n) internal returns (uint) {
        if (n == 0) return start;
        else if (n == 1) return start + 1;
        else return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
