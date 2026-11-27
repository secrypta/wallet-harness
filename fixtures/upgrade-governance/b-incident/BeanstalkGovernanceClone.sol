// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// -----------------------------------------------------------------------------
// Fixture provenance (see ./beanstalk-governance-victim/PROVENANCE.md for the full block)
//   Vector:  upgrade-governance   Tier: b-incident   Expected: VULNERABLE
//   Origin:  Beanstalk Farms flash-loan governance takeover, 2022-04-17, Ethereum, ~$182M
//            protocol loss (~$76-80M net to the attacker: 24,830 ETH + 36M BEAN). Beanstalk
//            governance counted voting weight from CURRENT deposited stake with no flash-
//            loan resistance and no timelock between a proposal and its execution. The
//            attacker flash-borrowed ~$1B, converted it into deposited stake to exceed the
//            supermajority instantly, then called emergencyCommit on a pre-submitted
//            malicious proposal. That proposal was DELEGATECALLED by the governance diamond,
//            so the attacker's init code ran in the protocol's own context and swept its
//            assets out - all in a single transaction.
//   Proof:   MECHANISM-LEVEL. A faithful minimized reproduction of the vector: instant
//            (no-timelock, no-snapshot) supermajority execution that delegatecalls an
//            attacker-supplied proposal in the protocol's context. The real Diamond/Silo
//            internals (Curve routing, BIP vote accounting) are abstracted.
//   On-chain (verified via read-only RPC, 2026-11-17):
//            Attack tx  0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7
//                       from 0x1c5dcdd006ea78a7e4783f9e6021c32935a10fb4 (attacker EOA),
//                       to   null (deploys the attack contract 0x79224bC0...a59dEf),
//                       block 14602790, 2022-04-17 12:24:16 UTC.
//            Malicious proposal contract 0xe5ecf73603d98a0128f05ed30506ac7a663dbb69;
//            Beanstalk (victim) 0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5.
//   Sources: CertiK; Veridise; Beosin; Coindesk; Cointelegraph (see PROVENANCE.md).
//   License: MIT (this repo). No third-party bytecode copied.
//
//   HOLDOUT: authored after the wal detectors froze at v0.1; wal was never tuned to it.
// -----------------------------------------------------------------------------

/// @dev Minimal stake/treasury token the governance custodies; deposited stake == votes.
contract BeanToken {
    string public name = "Beanstalk (minimized incident clone)";
    string public symbol = "BEAN";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "BEAN: insufficient allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "BEAN: insufficient balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
    }
}

/// @title MaliciousProposalInit - the attacker's BIP "init" code, run via delegatecall.
/// @notice When the governance diamond delegatecalls this on commit, it runs in the
///         governance's storage/authority context, so it can move the protocol's own
///         token balance out. Mirrors BIP-18's init contract that transferred Beanstalk's
///         assets to the attacker.
contract MaliciousProposalInit {
    function init(address token, address attacker) external {
        uint256 bal = BeanToken(token).balanceOf(address(this));
        BeanToken(token).transfer(attacker, bal);
    }
}

/// @title BeanstalkGovernanceClone - minimized Beanstalk-style on-chain governance.
/// @notice VULNERABLE policy: voting weight is read from CURRENT deposited stake (no
///         snapshot / no flash-loan resistance), and emergencyCommit executes a proposal
///         IMMEDIATELY with no timelock. The proposal is run by DELEGATECALL, so a caller
///         who reaches the supermajority in the same transaction (e.g. via a flash loan)
///         executes arbitrary code in the protocol's context. One instant majority ==
///         instant arbitrary execution == full drain.
contract BeanstalkGovernanceClone {
    BeanToken public immutable stakeToken;

    mapping(address => uint256) public deposited; // silo deposits == voting weight
    uint256 public totalDeposited;

    struct Proposal {
        address initContract;
        bool executed;
    }
    Proposal[] public proposals;

    constructor(BeanToken _stakeToken) {
        stakeToken = _stakeToken;
    }

    /// @notice Deposit stake into the silo (gains voting weight). In the incident the stake
    ///         was acquired with a flash loan and deposited within the attack transaction.
    function deposit(uint256 amount) external {
        stakeToken.transferFrom(msg.sender, address(this), amount);
        deposited[msg.sender] += amount;
        totalDeposited += amount;
    }

    /// @notice Submit a proposal (just records the init contract to delegatecall on commit).
    function propose(address initContract) external returns (uint256 id) {
        id = proposals.length;
        proposals.push(Proposal({initContract: initContract, executed: false}));
    }

    /// @notice VULNERABLE: execute immediately if caller holds > 2/3 of CURRENT total stake.
    ///         No snapshot, no timelock, no guardian - so flash-acquired stake counts and the
    ///         proposal's code is delegatecalled in this contract's context.
    function emergencyCommit(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "already executed");
        // supermajority of the instantaneous stake - the flash-loan-resistance gap.
        require(deposited[msg.sender] * 3 > totalDeposited * 2, "insufficient votes");
        p.executed = true;
        (bool ok, ) = p.initContract.delegatecall(
            abi.encodeWithSignature("init(address,address)", address(stakeToken), msg.sender)
        );
        require(ok, "commit failed");
    }
}
