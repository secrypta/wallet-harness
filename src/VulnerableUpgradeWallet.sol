// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableUpgradeWallet - upgradeable wallet with NO upgrade governance.
/// @notice The wallet holds the user's tokens and delegates all asset-moving logic to a
///         swappable `implementation` (module / delegate). A SINGLE key (`owner`) can
///         replace that implementation INSTANTLY - no timelock, no delay, no guardian, no
///         second signer. So the moment the owner key is compromised (phished seed, leaked
///         hot key, malicious signer), the attacker swaps in a malicious implementation and
///         the next `execute` sweeps the wallet. One compromised key == instant malicious
///         upgrade == full drain. This is the R10' drain surface: upgradeability without
///         governance.
contract VulnerableUpgradeWallet {
    address public owner;
    address public implementation;

    event Upgraded(address indexed newImplementation);

    constructor(address owner_, address implementation_) {
        owner = owner_;
        implementation = implementation_;
    }

    /// VULNERABLE: an instant, single-key implementation swap. No delay or guardian stands
    /// between a compromised key and a hostile implementation.
    function upgradeTo(address newImplementation) external {
        require(msg.sender == owner, "only owner");
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    /// Routes an asset operation through the current implementation (delegatecall: the
    /// implementation acts with the wallet's full authority over its own tokens).
    function execute(address token, address to, uint256 amount) external {
        require(msg.sender == owner, "only owner");
        (bool ok,) = implementation.delegatecall(
            abi.encodeWithSignature("execute(address,address,uint256)", token, to, amount)
        );
        require(ok, "exec failed");
    }
}
