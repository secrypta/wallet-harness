// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MonkeyDrainerNFTClone - minimized offline clone of the ERC-721 surface swept in
///        the Monkey Drainer NFT phishing-as-a-service drains (2022), for the
///        set-approval-for-all (b) real-incident fixture.
/// @notice NOT a toy pair: this is a faithful, minimized reproduction of the exact path the
///         Monkey Drainer kit used. Victims were lured into calling
///         `setApprovalForAll(operator, true)` (selector `0xa22cb465`) on an ERC-721 to a
///         malicious operator, which then `transferFrom`'d the victim's ENTIRE collection.
///         Only the operator-for-all + transferFrom surface needed to replay that path is
///         modeled here (no metadata, enumerable, or royalty logic). Provenance (incident,
///         selector, sources) in the sibling PROVENANCE.md. Offline only - no network, no
///         live RPC. Build/run in Docker.
contract MonkeyDrainerNFTClone {
    mapping(uint256 => address) private _owner;
    mapping(address => uint256) private _balance;
    mapping(address => mapping(address => bool)) private _operatorForAll;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /// @dev Test-only mint to seed the example victim's collection for the offline replay.
    function mint(address to, uint256 tokenId) external {
        require(to != address(0), "ERC721: mint to zero");
        require(_owner[tokenId] == address(0), "ERC721: already minted");
        _owner[tokenId] = to;
        _balance[to] += 1;
        emit Transfer(address(0), to, tokenId);
    }

    function ownerOf(uint256 tokenId) public view returns (address owner) {
        owner = _owner[tokenId];
        require(owner != address(0), "ERC721: nonexistent token");
    }

    function balanceOf(address owner) external view returns (uint256) {
        return _balance[owner];
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorForAll[owner][operator];
    }

    /// @notice selector 0xa22cb465 - the exact call the Monkey Drainer phishing UI induced
    ///         victims to sign, handing blanket authority over their whole collection.
    function setApprovalForAll(address operator, bool approved) external {
        _operatorForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /// @notice An operator-for-all can move any of the owner's tokens - this is what let the
    ///         drainer sweep entire collections after a single approval.
    function transferFrom(address from, address to, uint256 tokenId) external {
        address owner = ownerOf(tokenId);
        require(owner == from, "ERC721: transfer from wrong owner");
        require(to != address(0), "ERC721: transfer to zero");
        require(
            msg.sender == owner || _operatorForAll[owner][msg.sender],
            "ERC721: caller is not owner nor operator-for-all"
        );
        _balance[from] -= 1;
        _balance[to] += 1;
        _owner[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }
}
