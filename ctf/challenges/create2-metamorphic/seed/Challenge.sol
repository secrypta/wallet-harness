// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title Challenge - a wallet that lets an authorized trustee contract move its tokens.
/// @notice This is the VULNERABLE version. Your job is to fix `authorize` and `pull` so the
///         create2-metamorphic vector no longer works, WITHOUT breaking the legitimate flow.
///
///         Keep BOTH function signatures exactly as-is - the hidden grader calls them by
///         these names and arguments. You may change only the bodies. This is an [advanced]
///         challenge with TWO points to fix.
///
/// The intended use: the wallet authorizes a vetted trustee contract, which may later `pull`
/// tokens on the wallet's behalf. The bug below is that the wallet trusts the trustee's
/// ADDRESS forever - it never records WHAT CODE it vetted. If the code at that address is
/// later swapped for a drainer (modelled with `vm.etch` in the gate), the still-valid
/// authorization now points at hostile logic that pulls the full balance.
contract Challenge {
    address public immutable token;

    address public trustee;
    bytes32 public pinnedCodehash; // provided for your fix; unused in this vulnerable version

    constructor(address token_) {
        token = token_;
    }

    function authorize(address trustee_) external {
        // BUG: records only the address, not the code that was vetted at this address.
        trustee = trustee_;
    }

    function pull(address to, uint256 amount) external {
        // BUG: trusts the address regardless of what code now lives there.
        require(msg.sender == trustee, "pull: caller is not the trustee");
        IERC20Min(token).transfer(to, amount);
    }
}
