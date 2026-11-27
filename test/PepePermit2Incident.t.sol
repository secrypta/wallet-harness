// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ToyPermit2} from "../src/ToyPermit2.sol";

/// @title permit2-phishing tier (b): PEPE holder Permit2 phishing (2024-10-13, ~$1.39M).
/// @notice Minimized offline reproduction of the documented mechanism. The victim had the
///         standard `approve(Permit2, max)` on multiple tokens and signed ONE malicious
///         Permit2 `PermitBatch` off-chain (no tx, nothing in the wallet to inspect),
///         granting the attacker unbounded pull rights over PEPE + MSTR + APU at once. The
///         attacker submitted the signature and swept all three in one go. Reproduced via
///         this repo's ToyPermit2 AllowanceTransfer model (MIT, no AGPL/solmate). Verdict is
///         derived from the real outcome: all three balances emptied on a single signature.
contract PepePermit2IncidentTest is Test {
    uint256 constant PEPE_BAL = 1_200_000e18; // representative units, not exact
    uint256 constant MSTR_BAL = 150_000e18;
    uint256 constant APU_BAL = 40_000e18;

    bytes32 constant PERMIT_DETAILS_TYPEHASH =
        keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)");
    bytes32 constant PERMIT_BATCH_TYPEHASH = keccak256(
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    ToyPermit2 permit2;
    MockERC20 pepe;
    MockERC20 mstr;
    MockERC20 apu;
    uint256 constant OWNER_PK = 0x9E9E;
    address victim;
    address constant ATTACKER = address(0xBAD7A77);

    function _report(string memory target, bool drained) internal pure {
        string memory verdict = drained ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[permit2-phishing] target=", target, " verdict=", verdict));
    }

    function _buildBatch() internal view returns (ToyPermit2.PermitBatch memory batch) {
        ToyPermit2.PermitDetails[] memory details = new ToyPermit2.PermitDetails[](3);
        uint48 exp = uint48(block.timestamp + 365 days);
        details[0] = ToyPermit2.PermitDetails(address(pepe), type(uint160).max, exp, 0);
        details[1] = ToyPermit2.PermitDetails(address(mstr), type(uint160).max, exp, 0);
        details[2] = ToyPermit2.PermitDetails(address(apu), type(uint160).max, exp, 0);
        batch =
            ToyPermit2.PermitBatch({details: details, spender: ATTACKER, sigDeadline: block.timestamp + 365 days});
    }

    function _signBatch(ToyPermit2.PermitBatch memory batch) internal view returns (bytes memory sig) {
        bytes32[] memory detailHashes = new bytes32[](batch.details.length);
        for (uint256 i = 0; i < batch.details.length; i++) {
            detailHashes[i] = keccak256(
                abi.encode(
                    PERMIT_DETAILS_TYPEHASH,
                    batch.details[i].token,
                    batch.details[i].amount,
                    batch.details[i].expiration,
                    batch.details[i].nonce
                )
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_BATCH_TYPEHASH, keccak256(abi.encodePacked(detailHashes)), batch.spender, batch.sigDeadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _setup() internal {
        permit2 = new ToyPermit2();
        victim = vm.addr(OWNER_PK);
        pepe = new MockERC20();
        mstr = new MockERC20();
        apu = new MockERC20();
        pepe.mint(victim, PEPE_BAL);
        mstr.mint(victim, MSTR_BAL);
        apu.mint(victim, APU_BAL);
        // the one-time Permit2 approve the victim had already made on each token
        vm.startPrank(victim);
        pepe.approve(address(permit2), type(uint256).max);
        mstr.approve(address(permit2), type(uint256).max);
        apu.approve(address(permit2), type(uint256).max);
        vm.stopPrank();
    }

    function test_pepeVictim_oneSignature_drainsAllTokens() public {
        _setup();

        ToyPermit2.PermitBatch memory batch = _buildBatch();
        bytes memory sig = _signBatch(batch);

        // Attacker submits the SINGLE signature, then sweeps all three tokens.
        vm.startPrank(ATTACKER);
        permit2.permitBatch(victim, batch, sig);
        permit2.transferFrom(victim, ATTACKER, uint160(PEPE_BAL), address(pepe));
        permit2.transferFrom(victim, ATTACKER, uint160(MSTR_BAL), address(mstr));
        permit2.transferFrom(victim, ATTACKER, uint160(APU_BAL), address(apu));
        vm.stopPrank();

        bool drained =
            (pepe.balanceOf(victim) == 0 && mstr.balanceOf(victim) == 0 && apu.balanceOf(victim) == 0);
        _report("pepe-permit2-victim", drained);

        assertTrue(drained, "one Permit2 signature should drain all three tokens");
        assertEq(pepe.balanceOf(ATTACKER), PEPE_BAL, "attacker took PEPE");
        assertEq(mstr.balanceOf(ATTACKER), MSTR_BAL, "attacker took MSTR");
        assertEq(apu.balanceOf(ATTACKER), APU_BAL, "attacker took APU");
    }
}
