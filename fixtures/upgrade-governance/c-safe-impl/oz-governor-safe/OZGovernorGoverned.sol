// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Tier (c) genuinely-safe real code for the upgrade-governance vector.
//
// The safety-relevant machinery is UNMODIFIED OpenZeppelin v5.1.0:
//   source : github.com/OpenZeppelin/openzeppelin-contracts (tag v5.1.0, commit 69c8def5)
//   license: MIT (see ../../../vendor/oz/LICENSE and ../../../vendor/PROVENANCE.md)
//
// A full OpenZeppelin Governor stack (GovernorVotes + quorum + GovernorTimelockControl) owns
// the protected admin operation. This is a DISTINCT governance MECHANISM from the timelock- and
// AccessManager-gated fixtures: a protected change requires a token-weighted vote to pass
// (propose -> vote -> queue -> execute through the timelock), not just a role or a delay. The
// upgrade-governance vector (Audius-style instant single-key swap) is impossible: a lone key
// can neither call the protected op directly (only the timelock/governance executor may) nor
// pass a proposal without quorum + majority voting weight.
//
// The only authored code is the thin concrete Governor wiring (standard OZ override boilerplate),
// a minimal ERC20Votes token, and a governed vault whose `setImplementation` is `onlyGovernance`.
// None of OpenZeppelin's governance logic is modified.

import {Governor} from "../../../vendor/oz/governance/Governor.sol";
import {GovernorSettings} from "../../../vendor/oz/governance/extensions/GovernorSettings.sol";
import {GovernorCountingSimple} from "../../../vendor/oz/governance/extensions/GovernorCountingSimple.sol";
import {GovernorVotes} from "../../../vendor/oz/governance/extensions/GovernorVotes.sol";
import {GovernorVotesQuorumFraction} from
    "../../../vendor/oz/governance/extensions/GovernorVotesQuorumFraction.sol";
import {GovernorTimelockControl} from
    "../../../vendor/oz/governance/extensions/GovernorTimelockControl.sol";
import {TimelockController} from "../../../vendor/oz/governance/TimelockController.sol";
import {IVotes} from "../../../vendor/oz/governance/utils/IVotes.sol";
import {ERC20} from "../../../vendor/oz/token/ERC20/ERC20.sol";
import {ERC20Votes} from "../../../vendor/oz/token/ERC20/extensions/ERC20Votes.sol";
import {EIP712} from "../../../vendor/oz/utils/cryptography/EIP712.sol";

/// @title GovVotesToken - a minimal ERC20Votes governance token over unmodified OZ.
contract GovVotesToken is ERC20, ERC20Votes {
    constructor() ERC20("Gov", "GOV") EIP712("Gov", "1") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Votes) {
        super._update(from, to, value);
    }
}

/// @title GovGoverner - a canonical OZ Governor with token voting, quorum and a timelock.
contract GovGoverner is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    constructor(IVotes token_, TimelockController timelock_)
        Governor("GovGoverner")
        GovernorSettings(uint48(1), uint32(50), 0) // votingDelay=1 block, votingPeriod=50, threshold=0
        GovernorVotes(token_)
        GovernorVotesQuorumFraction(4) // 4% quorum
        GovernorTimelockControl(timelock_)
    {}

    // --- required OZ override boilerplate (unmodified super calls) ---

    function votingDelay() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingDelay();
    }

    function votingPeriod() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.votingPeriod();
    }

    function quorum(uint256 timepoint)
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(timepoint);
    }

    function proposalThreshold() public view override(Governor, GovernorSettings) returns (uint256) {
        return super.proposalThreshold();
    }

    function state(uint256 proposalId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (ProposalState)
    {
        return super.state(proposalId);
    }

    function proposalNeedsQueuing(uint256 proposalId)
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (bool)
    {
        return super.proposalNeedsQueuing(proposalId);
    }

    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint48) {
        return super._queueOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) {
        super._executeOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    function _executor() internal view override(Governor, GovernorTimelockControl) returns (address) {
        return super._executor();
    }
}

/// @title GovGovernedVault - a protected target whose admin op only governance (the timelock) can call.
contract GovGovernedVault {
    address public governance; // the TimelockController behind the Governor
    address public implementation; // the governance-protected pointer (the "upgrade" target)

    constructor(address governance_) {
        governance = governance_;
        implementation = address(this);
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "not governance");
        _;
    }

    /// @notice The sensitive governance operation (instant single-key swap must be impossible).
    function setImplementation(address impl) external onlyGovernance {
        implementation = impl;
    }
}
