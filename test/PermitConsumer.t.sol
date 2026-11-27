// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {UnboundedPermitRouter} from "../src/UnboundedPermitRouter.sol";
import {ScopedPermitRouter} from "../src/ScopedPermitRouter.sol";

/// @title permit-phishing consumer targets (R4), proven by test body.
/// @notice Models the on-chain permit CONSUMER (a relayer/router). Both targets submit the
///         owner's EIP-2612 permit; the only difference is how much they pull afterwards. The
///         vulnerable consumer sweeps the full balance (beyond the action); the safe consumer
///         pulls exactly the action amount and leaves the rest. The probe measures the real
///         on-chain outcome and derives the verdict.
contract PermitConsumerTest is Test {
    uint256 constant START_BALANCE = 100e18;
    uint256 constant ACTION_AMOUNT = 10e18; // what the interaction actually needs
    uint256 constant OWNER_PK = 0xA11CE;
    address constant RECIPIENT = address(0xF00D); // where the action is meant to pay
    address constant ATTACKER = address(0xA77ACC);

    function _digest(MockERC20 token, address owner, address spender, uint256 value, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(token.PERMIT_TYPEHASH(), owner, spender, value, token.nonces(owner), deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    }

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit-phishing] target=", target, " verdict=", verdict));
    }

    /// Vulnerable consumer: owner is lured into signing an unbounded-value permit; the router
    /// consumes it to sweep the owner's full balance to the attacker (beyond the action).
    function test_vulnerableConsumer_sweepsFullBalance() public {
        MockERC20 token = new MockERC20();
        UnboundedPermitRouter router = new UnboundedPermitRouter();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 deadline = block.timestamp + 1 days;
        uint256 signedValue = type(uint256).max; // owner lured into an unlimited permit
        bytes32 digest = _digest(token, owner, address(router), signedValue, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        router.relay(address(token), owner, signedValue, deadline, v, r, s, ATTACKER, ACTION_AMOUNT);

        uint256 ownerLeft = token.balanceOf(owner);
        bool drained = ownerLeft < START_BALANCE - ACTION_AMOUNT; // more than the action left
        _report("vulnerable-permit-consumer", drained);

        assertTrue(drained, "consumer should have pulled beyond the action amount");
        assertEq(token.balanceOf(ATTACKER), START_BALANCE, "attacker swept the whole balance");
        assertEq(ownerLeft, 0, "owner emptied");
    }

    /// Safe consumer: owner signs a permit for exactly the action amount; the router pulls
    /// exactly that and leaves the rest. Even an over-signed permit cannot pull more here.
    function test_safeConsumer_pullsOnlyActionAmount() public {
        MockERC20 token = new MockERC20();
        ScopedPermitRouter router = new ScopedPermitRouter();
        address owner = vm.addr(OWNER_PK);
        token.mint(owner, START_BALANCE);

        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = _digest(token, owner, address(router), ACTION_AMOUNT, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);

        router.relay(address(token), owner, deadline, v, r, s, RECIPIENT, ACTION_AMOUNT);

        uint256 ownerLeft = token.balanceOf(owner);
        bool drained = ownerLeft < START_BALANCE - ACTION_AMOUNT;
        _report("safe-permit-consumer", drained);

        assertFalse(drained, "safe consumer must pull only the action amount");
        assertEq(ownerLeft, START_BALANCE - ACTION_AMOUNT, "only the action amount left the owner");
        assertEq(token.balanceOf(RECIPIENT), ACTION_AMOUNT, "action paid exactly - not vacuous");
    }
}
