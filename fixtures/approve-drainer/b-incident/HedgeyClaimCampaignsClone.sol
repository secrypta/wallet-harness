// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HedgeyClaimCampaignsClone - minimized offline clone of the stale-approval surface
///        drained in the Hedgey Finance incident (2024-04-19), for the approve-drainer (b)
///        real-incident fixture.
/// @notice NOT our toy, and NOT copied from any third party (DeFiHackLabs is Apache-2.0 and was
///         used only as a FACTS reference). This is a faithful, minimized reproduction of the
///         ONE code-level flaw behind the drain: Hedgey's ClaimCampaigns contract granted an
///         ERC-20 approval to a campaign-supplied "locker" address when a campaign was created,
///         the `claimLockup` input (which carries that locker) was NOT validated, and when a
///         campaign was CANCELLED the contract returned the campaign's own tokens but DID NOT
///         revoke the standing approval. That residual, unrevoked allowance let the attacker's
///         contract `transferFrom` the ClaimCampaigns contract's remaining balance (pooled from
///         other campaigns). Only the approve-on-create / no-revoke-on-cancel surface is
///         modeled; the real vesting/lockup plans, flash-loan entry and multi-chain deploy are
///         omitted (irrelevant to the approve-drain path). Provenance (tx, addresses, sources,
///         on-chain Transfer log) in PROVENANCE.md. Offline only - no network. Build/run in Docker.
/// @dev    CALL SHAPES ARE FAITHFUL TO THE REAL CONTRACT. The real Hedgey ClaimCampaigns does not
///         use the bare `token.approve(...)` member form; it grants the allowance through the OZ
///         SafeERC20 library static helper `SafeERC20.safeIncreaseAllowance(IERC20(token), locker,
///         amount)` and pulls the deposit through its `TransferHelper.transferTokens(token, from,
///         address(this), amount)` library helper (which internally calls SafeERC20.safeTransferFrom)
///         - not a direct `transferFrom` member. A detector that scans only the bare member forms
///         is blind to this and MISSES the real drain; this clone reproduces the real library
///         forms so the committed gate exercises exactly that shape. (The toy pair in src/ keeps
///         the simpler member form, so both shapes stay covered.)
interface IERC20Min {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @dev Minimized stand-in for OpenZeppelin's SafeERC20 library - only the two members the real
///      ClaimCampaigns used. The allowance-grant is the LIBRARY STATIC form
///      `SafeERC20.safeIncreaseAllowance(token, spender, value)` (spender = 2nd arg), the shape
///      the real contract shipped. Behaviour is modeled, not copied from OZ.
library SafeERC20 {
    function safeIncreaseAllowance(IERC20Min token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        require(token.approve(spender, newAllowance), "SafeERC20: approve failed");
    }

    function safeTransferFrom(IERC20Min token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "SafeERC20: transferFrom failed");
    }
}

/// @dev Minimized stand-in for Hedgey's own TransferHelper library. The deposit is pulled into
///      the contract through `TransferHelper.transferTokens(token, from, address(this), amount)`,
///      a library helper that forwards to SafeERC20.safeTransferFrom - NOT a direct transferFrom
///      member on the contract. This is the custody form the real incident used.
library TransferHelper {
    function transferTokens(IERC20Min token, address from, address to, uint256 amount) internal {
        SafeERC20.safeTransferFrom(token, from, to, amount);
    }
}

/// @dev Minimal ERC-20 (USDC-like, 6 decimals) - the asset the ClaimCampaigns contract pooled
///      and that the stale approval drained.
contract UsdcLikeToken {
    string public name = "USD Coin (minimized incident clone)";
    string public symbol = "USDC";
    uint8 public constant decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: insufficient balance");
        unchecked { balanceOf[msg.sender] -= amount; balanceOf[to] += amount; }
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ERC20: insufficient allowance");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        require(balanceOf[from] >= amount, "ERC20: insufficient balance");
        unchecked { balanceOf[from] -= amount; balanceOf[to] += amount; }
        emit Transfer(from, to, amount);
        return true;
    }
}

/// @notice Minimized clone of the Hedgey ClaimCampaigns contract. Campaigns deposit tokens into
///         the shared contract balance. On create, the contract approves a campaign-supplied
///         `locker` (unvalidated) so the locker can later move claimed tokens. On cancel, the
///         campaign's deposit is returned to its creator but the approval to `locker` is NOT
///         cleared - the exact stale-approval bug.
contract HedgeyClaimCampaignsClone {
    IERC20Min public immutable token;

    struct Campaign {
        address creator;
        uint256 amount;
        bool active;
    }

    mapping(bytes16 => Campaign) public campaigns;

    constructor(IERC20Min _token) {
        token = _token;
    }

    /// @notice Create a campaign. `locker` comes straight from the caller's claimLockup with NO
    ///         validation, and is approved to move up to `amount`. (As shipped.)
    function createLockedCampaign(bytes16 id, uint256 amount, address locker) external {
        // Pull the creator's deposit into the shared contract balance - via the TransferHelper
        // library helper (SafeERC20.safeTransferFrom under the hood), exactly as the real
        // ClaimCampaigns did (not a direct `token.transferFrom` member call).
        TransferHelper.transferTokens(token, msg.sender, address(this), amount);
        campaigns[id] = Campaign({creator: msg.sender, amount: amount, active: true});

        // BUG (as shipped): grant a standing approval to an unvalidated, caller-controlled
        // address. The attacker supplies their own contract here. The grant uses the OZ SafeERC20
        // library static form (spender is the 2nd argument), the real contract's shape.
        SafeERC20.safeIncreaseAllowance(token, locker, amount);
    }

    /// @notice Cancel a campaign: return the campaign's own deposit to its creator.
    /// @dev BUG (as shipped): the approval granted to `locker` in createLockedCampaign is NEVER
    ///      revoked here. It survives the cancel, standing against the contract's whole balance.
    function cancelCampaign(bytes16 id) external {
        Campaign storage c = campaigns[id];
        require(c.active && c.creator == msg.sender, "not creator / inactive");
        c.active = false;
        token.transfer(c.creator, c.amount);
        // (missing) token.approve(locker, 0);  <-- the fix Hedgey later shipped
    }
}
