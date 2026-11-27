// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MockERC721 - minimal ERC-721 used by the set-approval-for-all corpus vector.
/// @notice Toy NFT for test scenarios only. Open `mint` is intentional so tests can
///         give a wallet a collection in one call; never use this on a real network.
///         It implements the two distinct authorization paths ERC-721 offers:
///           * `approve(operator, tokenId)`      - scoped to ONE token, and
///           * `setApprovalForAll(operator, bool)` - a blanket, standing authority over
///             EVERY token the owner holds now or later.
///         The second path is the vector: a single `setApprovalForAll(.., true)` to a
///         malicious operator hands over the owner's whole collection, off-screen and
///         until explicitly revoked.
contract MockERC721 {
    string public name = "Mock Test NFT";
    string public symbol = "MNFT";

    // tokenId => current owner
    mapping(uint256 => address) private _owner;
    // owner => number of tokens held
    mapping(address => uint256) private _balance;
    // tokenId => single approved operator (scoped authority, cleared on transfer)
    mapping(uint256 => address) private _tokenApproval;
    // owner => operator => blanket authority over ALL of owner's tokens
    mapping(address => mapping(address => bool)) private _operatorForAll;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /// @notice Toy mint: assigns `tokenId` to `to`. Test-only, no access control.
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
        require(owner != address(0), "ERC721: zero address");
        return _balance[owner];
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owner[tokenId] != address(0), "ERC721: nonexistent token");
        return _tokenApproval[tokenId];
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorForAll[owner][operator];
    }

    /// @notice Scoped authority: lets `operator` move exactly `tokenId`. Only the token
    ///         owner (or an existing operator-for-all) may set it. This is the bounded,
    ///         defensible authorization path.
    function approve(address operator, uint256 tokenId) external {
        address owner = ownerOf(tokenId);
        require(
            msg.sender == owner || _operatorForAll[owner][msg.sender],
            "ERC721: approve caller is not owner nor operator-for-all"
        );
        _tokenApproval[tokenId] = operator;
        emit Approval(owner, operator, tokenId);
    }

    /// @notice Blanket authority: lets `operator` move EVERY token `msg.sender` owns
    ///         (present and future) until revoked. Convenient and, to a malicious
    ///         operator, a full-collection drain switch - that is the vector.
    function setApprovalForAll(address operator, bool approved) external {
        require(operator != msg.sender, "ERC721: approve to caller");
        _operatorForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    /// @notice Moves `tokenId` from `from` to `to`. Permitted when the caller is the
    ///         token owner, the single approved operator for this token, OR an
    ///         operator-for-all of the owner. The per-token approval is cleared on move.
    function transferFrom(address from, address to, uint256 tokenId) external {
        address owner = ownerOf(tokenId);
        require(owner == from, "ERC721: transfer from wrong owner");
        require(to != address(0), "ERC721: transfer to zero");
        require(
            msg.sender == owner
                || _tokenApproval[tokenId] == msg.sender
                || _operatorForAll[owner][msg.sender],
            "ERC721: caller is not owner nor approved"
        );

        // clear the single-token approval (standard ERC-721 behaviour)
        delete _tokenApproval[tokenId];

        _balance[from] -= 1;
        _balance[to] += 1;
        _owner[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }
}
