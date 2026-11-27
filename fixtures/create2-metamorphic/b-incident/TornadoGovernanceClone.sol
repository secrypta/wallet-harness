// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title create2-metamorphic (b) HOLDOUT fixture - Tornado Cash governance takeover (2023-05-20).
/// @notice Minimized, fully OFFLINE model of the documented metamorphic-contract governance attack.
///         The attacker published a governance proposal whose logic lived at a CREATE2-deterministic
///         address holding *benign* code at vote time (it looked identical to an earlier, already
///         trusted emergency-stop proposal). Token holders voted it in. After the vote, the attacker
///         SELFDESTRUCTed the benign code and redeployed *malicious* code at the same address; when
///         governance executed the (approved) proposal, the mutated code - running with the
///         proposal's privileges - minted the attacker an overwhelming number of votes, seizing the
///         governance. See PROVENANCE.md for the public post-mortem, tx hashes and addresses.
///
///         EIP-6780 caveat (same modeling convention as the dev create2 fixture): post-Cancun the
///         literal SELFDESTRUCT-then-redeploy-at-the-same-address trick is restricted, so code
///         mutation at a fixed address is modeled with a swappable implementation. The effective
///         code identity is the implementation codehash, standing in for EXTCODEHASH(proposal).
///         This reproduces the shared mechanism: governance confers authority on an address whose
///         code can change between approval and execution.
///
///         HOLDOUT: authored after the wal detectors froze at v0.1; wal was NOT tuned to pass it
///         (label=vuln -> expect VULNERABLE). Self-contained; no third-party source copied.

/// @dev Minimal governance token tracking vote weight. Not a full ERC-20; only what the replay needs.
contract GovToken {
    mapping(address => uint256) public votesOf;
    uint256 public totalVotes;

    function mint(address to, uint256 amount) external {
        votesOf[to] += amount;
        totalVotes += amount;
    }
}

interface IProposalLogic {
    /// @notice Executed by governance in the proposal's own privileged context.
    function run(address gov) external;
}

/// @dev Benign, trusted-looking proposal logic: a no-op "emergency stop" placeholder. This is the
///      code present at the deterministic address at vote time.
contract BenignProposalLogic is IProposalLogic {
    event EmergencyStop();

    function run(address) external override {
        emit EmergencyStop(); // harmless
    }
}

/// @dev Malicious proposal logic swapped in after the vote: mints an overwhelming vote balance to
///      the attacker using the privilege governance grants the approved, executing proposal.
contract MaliciousProposalLogic is IProposalLogic {
    address public immutable attacker;
    uint256 public immutable grab;

    constructor(address attacker_, uint256 grab_) {
        attacker = attacker_;
        grab = grab_;
    }

    function run(address gov) external override {
        GovernanceClone(gov).mintVotes(attacker, grab);
    }
}

/// @dev Swappable implementation at a fixed address - models metamorphic code mutation (EIP-6780
///      caveat above). `impl` is the current runtime code identity at this address.
contract MetamorphicProposal is IProposalLogic {
    address public impl;
    address public immutable owner;

    constructor(address initialImpl) {
        impl = initialImpl;
        owner = msg.sender;
    }

    /// @notice Attacker mutates the code identity at this fixed address (benign -> malicious).
    function swapCode(address newImpl) external {
        require(msg.sender == owner, "only owner");
        impl = newImpl;
    }

    function run(address gov) external override {
        // Governance executes an approved proposal via delegatecall (as the real Tornado
        // governance did): the current implementation's code runs in THIS proposal's context,
        // so its privileged calls carry this approved proposal's identity as msg.sender.
        (bool ok, ) = impl.delegatecall(abi.encodeWithSelector(IProposalLogic.run.selector, gov));
        require(ok, "proposal delegatecall failed");
    }
}

/// @dev Minimized governance: a proposal is approved by vote, then executed. The executing proposal
///      is trusted to perform privileged actions (mintVotes) - exactly the authority the real
///      Tornado governance conferred on an approved proposal's code when it executed it.
contract GovernanceClone {
    GovToken public immutable token;
    address public approvedProposal;
    bool public executed;

    constructor(GovToken token_) {
        token = token_;
    }

    /// @notice Approve the proposal address after a passing vote (the address is fixed/deterministic;
    ///         its CODE is what the attacker later mutates).
    function approve(address proposal) external {
        approvedProposal = proposal;
    }

    /// @notice Privileged action available only to the currently-executing approved proposal.
    function mintVotes(address to, uint256 amount) external {
        require(msg.sender == approvedProposal, "only approved proposal");
        token.mint(to, amount);
    }

    /// @notice Execute the approved proposal - runs whatever code currently sits at that address.
    function execute() external {
        require(approvedProposal != address(0), "no proposal");
        executed = true;
        IProposalLogic(approvedProposal).run(address(this));
    }
}
