// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Permit2} from "../fixtures/vendor/permit2/src/Permit2.sol";

/// @title Permit2CompileAnchor - forces the vendored Permit2 to be compiled.
/// @notice The vendored Uniswap Permit2 pins an EXACT `pragma solidity 0.8.17`. Our pinned
///         forge-std (v1.9.4) hits "stack too deep" under 0.8.17, so the tier-(c) test cannot
///         import Permit2 directly (that would drag forge-std into Permit2's 0.8.17 compile
///         subgraph). Instead the test deploys Permit2 by artifact via `deployCode(...)` at
///         0.8.24 with forge-std intact. This anchor simply imports Permit2 in a forge-std-
///         free 0.8.17 unit so Foundry emits its artifact for `deployCode` to find. It is
///         never deployed itself.
contract Permit2CompileAnchor {}
