// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    LibCloneFactory,
    PingImpl,
    EvilImpl
} from "../fixtures/create2-metamorphic/c-safe-impl/solady-libclone-safe/LibCloneFactory.sol";
import {
    OZClonesFactory,
    PingImpl as OZPingImpl,
    EvilImpl as OZEvilImpl
} from "../fixtures/create2-metamorphic/c-safe-impl/oz-clones-safe/OZClonesFactory.sol";
import {
    Create3Factory,
    PingImpl as C3PingImpl,
    EvilImpl as C3EvilImpl
} from "../fixtures/create2-metamorphic/c-safe-impl/solady-create3-safe/Create3Factory.sol";

/// @title create2-metamorphic tier (c): canonical CREATE2 clones are immutable (Solady
///        LibClone, holdout precision).
/// @notice A deterministic minimal-proxy clone has no `selfdestruct`, so its deterministic
///         address cannot be destroyed and redeployed with different code - the metamorphic
///         swap a prior approval would be exposed to is impossible. The test deploys a clone
///         (works, non-vacuous), confirms the predicted address matches, then tries to redeploy
///         DIFFERENT code at the same salt/address and confirms it fails and the code is
///         unchanged. The harness must stay silent (BLOCKED) on legitimate CREATE2 usage.
contract RealSafeCreate2MetamorphicTest is Test {
    bytes32 constant SALT = keccak256("wal.create2.precision.salt");

    function _report(string memory target, bool metamorphosed) internal pure {
        string memory verdict = metamorphosed ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[create2-metamorphic] target=", target, " verdict=", verdict));
    }

    function test_soladyLibClone_deterministicCloneIsImmutable() public {
        LibCloneFactory factory = new LibCloneFactory();
        PingImpl ping = new PingImpl();
        EvilImpl evil = new EvilImpl();

        address predicted = factory.predict(address(ping), SALT);
        address clone = factory.deployDeterministic(address(ping), SALT);
        assertEq(clone, predicted, "clone lands at the predicted deterministic address");
        assertEq(PingImpl(clone).ping(), 42, "clone delegates to the approved implementation");

        bytes32 codehashBefore = clone.codehash;

        // Metamorphic attempt (a): redeploy the SAME (impl, salt) - CREATE2 to the occupied
        // address fails (the clone has no selfdestruct to vacate it), so the approved address
        // cannot be re-created and then replaced.
        (bool okSameSalt,) = address(factory).call(
            abi.encodeWithSignature("deployDeterministic(address,bytes32)", address(ping), SALT)
        );

        // Metamorphic attempt (b): deploy DIFFERENT code at the same salt. Because LibClone
        // bakes the implementation into the init code, a different impl derives a DIFFERENT
        // address - it can never occupy the approved clone's address with hostile code.
        address evilAddr = factory.deployDeterministic(address(evil), SALT);

        bool metamorphosed =
            okSameSalt || (evilAddr == clone) || (clone.codehash != codehashBefore);
        _report("solady-libclone-safe", metamorphosed);

        assertFalse(metamorphosed, "canonical CREATE2 clone address can never hold different code");
        assertFalse(okSameSalt, "redeploy at the occupied deterministic address must fail");
        assertTrue(evilAddr != clone, "different code derives a different address, not the approved one");
        assertEq(clone.codehash, codehashBefore, "code at the approved address is unchanged");
        assertEq(PingImpl(clone).ping(), 42, "still the original, approved implementation");
    }

    /// @notice Same precision check on the OpenZeppelin `Clones` library (a different canonical
    ///         implementation of the immutable EIP-1167 minimal-proxy guarantee).
    function test_ozClones_deterministicCloneIsImmutable() public {
        OZClonesFactory factory = new OZClonesFactory();
        OZPingImpl ping = new OZPingImpl();
        OZEvilImpl evil = new OZEvilImpl();

        address predicted = factory.predict(address(ping), SALT);
        address clone = factory.deployDeterministic(address(ping), SALT);
        assertEq(clone, predicted, "clone lands at the predicted deterministic address");
        assertEq(OZPingImpl(clone).ping(), 42, "clone delegates to the approved implementation");

        bytes32 codehashBefore = clone.codehash;

        // (a) redeploy SAME (impl, salt): CREATE2 to the occupied address fails (no selfdestruct
        //     to vacate it), so the approved address cannot be re-created and then replaced.
        (bool okSameSalt,) = address(factory).call(
            abi.encodeWithSignature("deployDeterministic(address,bytes32)", address(ping), SALT)
        );

        // (b) DIFFERENT code at the same salt: OZ bakes the impl into the init code, so a
        //     different impl derives a DIFFERENT address - never the approved clone's.
        address evilAddr = factory.deployDeterministic(address(evil), SALT);

        bool metamorphosed =
            okSameSalt || (evilAddr == clone) || (clone.codehash != codehashBefore);
        _report("oz-clones-safe", metamorphosed);

        assertFalse(metamorphosed, "canonical CREATE2 clone address can never hold different code");
        assertFalse(okSameSalt, "redeploy at the occupied deterministic address must fail");
        assertTrue(evilAddr != clone, "different code derives a different address, not the approved one");
        assertEq(clone.codehash, codehashBefore, "code at the approved address is unchanged");
        assertEq(OZPingImpl(clone).ping(), 42, "still the original, approved implementation");
    }

    /// @notice Solady CREATE3: the deterministic address depends only on (salt, deployer),
    ///         independent of init code. A second deploy at the same salt - even with DIFFERENT
    ///         code - targets the SAME address and fails (slot occupied, nothing self-destructs).
    ///         A distinct deterministic-deploy mechanism from the EIP-1167 clones above.
    function test_soladyCreate3_deterministicDeployIsImmutable() public {
        Create3Factory factory = new Create3Factory();

        address predicted = factory.predict(SALT);
        address deployed = factory.deployDeterministic(type(C3PingImpl).creationCode, SALT);
        assertEq(deployed, predicted, "deploys at the predicted CREATE3 address");
        assertEq(C3PingImpl(deployed).ping(), 42, "deployed the approved implementation");

        bytes32 codehashBefore = deployed.codehash;

        // (a) Redeploy the SAME code at the same salt -> fails (deterministic slot occupied).
        (bool okSameSalt,) = address(factory).call(
            abi.encodeWithSignature(
                "deployDeterministic(bytes,bytes32)", type(C3PingImpl).creationCode, SALT
            )
        );

        // (b) Deploy DIFFERENT code at the same salt. CREATE3 keys the address on salt+deployer,
        //     so this targets the SAME address and also fails - it can never replace the code.
        (bool okDiffCode,) = address(factory).call(
            abi.encodeWithSignature(
                "deployDeterministic(bytes,bytes32)", type(C3EvilImpl).creationCode, SALT
            )
        );

        bool metamorphosed = okSameSalt || okDiffCode || (deployed.codehash != codehashBefore);
        _report("solady-create3-safe", metamorphosed);

        assertFalse(metamorphosed, "CREATE3 deterministic address can never hold different code");
        assertFalse(okSameSalt, "redeploy same code at the occupied CREATE3 slot must fail");
        assertFalse(okDiffCode, "redeploy different code at the same CREATE3 salt must fail");
        assertEq(deployed.codehash, codehashBefore, "code at the approved address is unchanged");
        assertEq(C3PingImpl(deployed).ping(), 42, "still the original, approved implementation");
    }
}
