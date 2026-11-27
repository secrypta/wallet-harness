// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../../vendor/oz/token/ERC20/ERC20.sol";
import {ERC20Votes} from "../../vendor/oz/token/ERC20/extensions/ERC20Votes.sol";
import {EIP712} from "../../vendor/oz/utils/cryptography/EIP712.sol";

/// @title OzVotesTokenFixture - concrete ERC20Votes governance token over the UNMODIFIED vendored
///        OpenZeppelin ERC20Votes. Real-safe (tier c) vehicle for the blind-eth-sign vector.
/// @notice A real signed-authorization surface: `Votes.delegateBySig` lets an off-chain signature
///         redirect an account's voting power. The safety-critical part is that the signature must
///         cover the FULLY-TYPED EIP-712 `Delegation(address delegatee,uint256 nonce,uint256 expiry)`
///         digest, which is unmodified OpenZeppelin v5.1.0 (fixtures/vendor/oz/, MIT; see
///         fixtures/vendor/PROVENANCE.md). This subclass adds ONLY a test-only `mint` and the
///         constructor; it changes none of the delegation/signature logic.
///
///         The blind-eth-sign danger is a victim tricked into an eth_sign (personal_sign) over an
///         opaque hash. A blind signature does NOT cover the typed Delegation digest, so
///         `ECDSA.recover` inside `delegateBySig` yields a signer OTHER than the victim - it cannot
///         redirect the victim's voting power to the phisher. Distinct from the existing
///         blind-eth-sign holdouts (OZ EIP712+ECDSA wallet, Uniswap Permit2, Solady EIP712): this
///         exercises the canonical governance-delegation-by-signature surface (OZ Votes), a
///         different real verifier wal was never tuned against.
contract OzVotesTokenFixture is ERC20Votes {
    constructor() ERC20("Gov Token", "GOV") EIP712("Gov Token", "1") {}

    /// @dev Test-only mint (no access control on purpose; fixtures only).
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
