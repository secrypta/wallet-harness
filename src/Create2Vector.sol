// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// CREATE2 / metamorphic "approved-address code swap" vector (#10). Toy targets.
//
// CREATE2 deploys to a deterministic address derived from (deployer, salt, initcode). A
// victim grants a standing approval to (or otherwise trusts) a contract carrying BENIGN code
// at such an address; the attacker then mutates the code at that SAME address to a drainer
// and spends the standing approval.
//
// HONESTY (Cancun / EIP-6780, 2024): the literal SELFDESTRUCT-then-redeploy-at-same-address
// trick no longer works on post-Cancun EVMs except within the creating tx. We therefore model
// code mutation at a fixed address with a swappable implementation pointer (delegatecall). The
// "effective code identity" is the implementation's codehash, exposed via codeId(); it stands
// in for EXTCODEHASH(address) and is what a codehash-pinning wallet records and re-checks. This
// is mechanism-faithful and class-level; see each PROVENANCE.md. (The fresh-CREATE2-address
// blocklist-evasion variant documented by Scam Sniffer is unaffected by EIP-6780.)

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @dev Benign code initially living at the approved address: a harmless no-op service.
contract BenignLogic {
    event Pinged();
    function ping() external {
        emit Pinged();
    }
}

/// @dev Drainer code swapped in later. Run via delegatecall from MetamorphicSpender, so the
///      token sees the (already-approved) spender address as msg.sender and the standing
///      allowance is spent.
contract DrainerLogic {
    function drain(address token, address victim, address attacker) external {
        uint256 bal = IERC20(token).balanceOf(victim);
        IERC20(token).transferFrom(victim, attacker, bal);
    }
}

/// @title MetamorphicSpender - an approved spender whose executed code can change at a fixed
///        address (models a CREATE2/metamorphic contract).
contract MetamorphicSpender {
    address public impl;
    address public immutable deployer;

    constructor(address impl_) {
        impl = impl_;
        deployer = msg.sender;
    }

    /// The metamorphic swap: the attacker replaces benign code with a drainer at the same addr.
    function swapCode(address impl_) external {
        require(msg.sender == deployer, "only deployer");
        impl = impl_;
    }

    /// Effective code identity a codehash-pinning wallet should track (stands in for EXTCODEHASH).
    function codeId() external view returns (bytes32) {
        return impl.codehash;
    }

    /// Execute the current implementation IN THIS ADDRESS'S CONTEXT, so a standing ERC-20
    /// allowance granted to this address is spent by whatever code currently sits here.
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = impl.delegatecall(data);
        require(ok, "exec failed");
        return ret;
    }
}

/// @title VulnerableApprover - grants a standing approval to a contract WITHOUT pinning code.
/// @notice If that contract is (or becomes) metamorphic, the approval now backs hostile code at
///         the same address. This models a wallet that hands out a raw allowance and never
///         re-checks the spender's code.
contract VulnerableApprover {
    function trustAndApprove(address token, address spender, uint256 amount) external {
        IERC20(token).approve(spender, amount);
    }
}

interface ICodeId {
    function codeId() external view returns (bytes32);
}

/// @title CodehashPinnedApprover - the toy codehash-pinning defense.
/// @notice Grants NO raw standing allowance to a mutable-code address. Instead it records the
///         spender's effective code identity at trust time and gates every outflow on the code
///         being unchanged. After a metamorphic swap the identity differs, so the guarded
///         settlement reverts and nothing leaves.
contract CodehashPinnedApprover {
    mapping(address => bytes32) public pinned; // spender => code identity at trust time

    function trust(address spender) external {
        pinned[spender] = ICodeId(spender).codeId();
    }

    function settle(address token, address spender, address to, uint256 amount) external {
        require(pinned[spender] != 0, "untrusted spender");
        require(ICodeId(spender).codeId() == pinned[spender], "codehash changed - metamorphic swap");
        IERC20(token).transfer(to, amount);
    }
}
