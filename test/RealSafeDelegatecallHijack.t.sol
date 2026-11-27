// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20} from "../src/MockERC20.sol";
import {ERC7821} from "../fixtures/vendor/solady-accounts/accounts/ERC7821.sol";
import {SoladyERC7821Wallet} from
    "../fixtures/delegatecall-hijack/c-safe-impl/solady-erc7821-safe/SoladyERC7821Wallet.sol";
import {ERC1967Proxy} from "../fixtures/vendor/oz/proxy/ERC1967/ERC1967Proxy.sol";
import {OZERC1967ProxyWallet} from
    "../fixtures/delegatecall-hijack/c-safe-impl/oz-erc1967-proxy-safe/OZERC1967ProxyWallet.sol";
import {SoladyUUPSWallet} from
    "../fixtures/delegatecall-hijack/c-safe-impl/solady-uups-proxy-safe/SoladyUUPSWallet.sol";
import {
    TransparentUpgradeableProxy,
    ITransparentUpgradeableProxy
} from "../fixtures/vendor/oz/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "../fixtures/vendor/oz/proxy/transparent/ProxyAdmin.sol";
import {
    TUPWallet,
    TUPWalletV2
} from "../fixtures/delegatecall-hijack/c-safe-impl/oz-transparent-proxy-safe/OZTransparentProxyWallet.sol";

/// @dev A draining UUPS implementation an attacker would try to swap in to redirect the proxy's
///      delegatecall sink. It is never installed - the attacker cannot pass `_authorizeUpgrade`.
contract EvilUpgradeImpl {
    function sweep(address, address) external {}
}

/// @dev If this probe were DELEGATECALLED by the wallet, writing slot 0 would overwrite the
///      wallet's `owner` (same layout) - the delegatecall-hijack takeover. Through a plain
///      `call` it only touches its own storage, so the wallet is unaffected.
contract WalletTakeoverProbe {
    address public owner; // slot 0 - mirrors the wallet's `owner` slot
    bool public ran;

    function hijack(address newOwner) external {
        owner = newOwner;
        ran = true;
    }
}

/// @title delegatecall-hijack tier (c): canonical ERC-7821 executor uses `call`, not
///        delegatecall (Solady, holdout precision).
/// @notice A legitimate owner batch executes (non-vacuous). An owner-approved action routed to
///         a "takeover" probe cannot rewrite the wallet (ERC-7821 executes via `call`, so the
///         probe runs in ITS OWN storage): the wallet's owner and balance are untouched. The
///         harness must stay silent. Verdict derived from the real outcome.
contract RealSafeDelegatecallHijackTest is Test {
    uint256 constant WALLET_BALANCE = 400_000e18;
    uint256 constant LEGIT_XFER = 1_000e18;
    address constant OWNER = address(0x0E7E);
    address constant RECIPIENT = address(0xBEEF);
    address constant ATTACKER = address(0xBAD55);

    bytes32 constant SINGLE_BATCH_MODE =
        bytes32(0x0100000000000000000000000000000000000000000000000000000000000000);

    function _report(string memory target, bool hijacked) internal pure {
        string memory verdict = hijacked ? "VULNERABLE" : "BLOCKED";
        console.log(string.concat("[delegatecall-hijack] target=", target, " verdict=", verdict));
    }

    function _encode(ERC7821.Call[] memory calls) internal pure returns (bytes memory) {
        return abi.encode(calls);
    }

    function test_soladyERC7821_executesViaCall_noDelegatecallHijack() public {
        MockERC20 token = new MockERC20();
        SoladyERC7821Wallet wallet = new SoladyERC7821Wallet(OWNER);
        WalletTakeoverProbe probe = new WalletTakeoverProbe();
        token.mint(address(wallet), WALLET_BALANCE);

        // Legit owner batch: move a small amount out - proves execute works (non-vacuous).
        ERC7821.Call[] memory legit = new ERC7821.Call[](1);
        legit[0] = ERC7821.Call({
            to: address(token),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT, LEGIT_XFER)
        });
        vm.prank(OWNER);
        wallet.execute(SINGLE_BATCH_MODE, _encode(legit));
        assertEq(token.balanceOf(RECIPIENT), LEGIT_XFER, "legit batch must execute");

        // Hijack attempt: owner is tricked into an action targeting the takeover probe. Because
        // ERC-7821 executes via `call`, the probe runs in its own context - it cannot rewrite
        // the wallet's owner or sweep its balance.
        ERC7821.Call[] memory evil = new ERC7821.Call[](1);
        evil[0] = ERC7821.Call({
            to: address(probe),
            value: 0,
            data: abi.encodeWithSignature("hijack(address)", ATTACKER)
        });
        vm.prank(OWNER);
        wallet.execute(SINGLE_BATCH_MODE, _encode(evil));

        bool hijacked = (wallet.owner() != OWNER) || (token.balanceOf(address(wallet)) != WALLET_BALANCE - LEGIT_XFER);
        _report("solady-erc7821-safe", hijacked);

        assertFalse(hijacked, "call-based execution must not allow a delegatecall takeover");
        assertEq(wallet.owner(), OWNER, "wallet owner unchanged (ran via call, not delegatecall)");
        assertTrue(probe.ran(), "the probe did run - in its own context");
        assertEq(probe.owner(), ATTACKER, "the write landed in the probe's storage, not the wallet's");
    }

    /// @notice OpenZeppelin ERC1967Proxy + UUPS: a proxy USES delegatecall, but only to its
    ///         MANAGED implementation slot. An attacker can neither redirect that sink (upgrade
    ///         is owner-gated) nor request a delegatecall operation (the wallet executes owner
    ///         ops via plain `call`). Precision: a real proxy must not be flagged as a hijack.
    function test_ozERC1967Proxy_delegatecallTargetIsManaged_noHijack() public {
        MockERC20 token = new MockERC20();
        OZERC1967ProxyWallet impl = new OZERC1967ProxyWallet();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(OZERC1967ProxyWallet.initialize, (OWNER))
        );
        OZERC1967ProxyWallet wallet = OZERC1967ProxyWallet(address(proxy));
        token.mint(address(wallet), WALLET_BALANCE);

        // Non-vacuous: a legit owner operation (plain call) moves a small amount out.
        vm.prank(OWNER);
        wallet.execute(
            address(token), 0, abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT, LEGIT_XFER)
        );
        assertEq(token.balanceOf(RECIPIENT), LEGIT_XFER, "legit owner op executes");

        // (a) Attacker tries to redirect the delegatecall sink by upgrading to a draining impl.
        //     `_authorizeUpgrade` is owner-gated, so the swap reverts and the sink is unchanged.
        EvilUpgradeImpl evil = new EvilUpgradeImpl();
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("not owner"));
        wallet.upgradeToAndCall(
            address(evil), abi.encodeWithSignature("sweep(address,address)", address(token), ATTACKER)
        );

        // (b) Owner routes an op to a storage-takeover probe. Because `execute` uses a plain
        //     `call` (no delegatecall operation mode), the probe runs in ITS OWN storage.
        WalletTakeoverProbe probe = new WalletTakeoverProbe();
        vm.prank(OWNER);
        wallet.execute(address(probe), 0, abi.encodeWithSignature("hijack(address)", ATTACKER));

        bool hijacked = (wallet.owner() != OWNER) || (wallet.version() != 1)
            || (token.balanceOf(address(wallet)) != WALLET_BALANCE - LEGIT_XFER);
        _report("oz-erc1967-proxy-safe", hijacked);

        assertFalse(hijacked, "proxy delegatecalls only its managed impl; no hijack");
        assertEq(wallet.owner(), OWNER, "wallet owner unchanged");
        assertEq(wallet.version(), 1, "implementation (delegatecall target) unchanged");
        assertEq(probe.owner(), ATTACKER, "the takeover write landed in the probe's own storage");
    }

    /// @notice Solady's INDEPENDENT (non-OZ) UUPS proxy mixin behind an ERC1967Proxy. Same
    ///         precision point as the OZ fixture, on a different codebase's proxy mechanism: the
    ///         proxy delegatecalls only its managed implementation slot; the sink cannot be
    ///         redirected (upgrade owner-gated) and owner ops run via plain `call`.
    function test_soladyUUPS_delegatecallTargetIsManaged_noHijack() public {
        MockERC20 token = new MockERC20();
        SoladyUUPSWallet impl = new SoladyUUPSWallet();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(SoladyUUPSWallet.initialize, (OWNER))
        );
        SoladyUUPSWallet wallet = SoladyUUPSWallet(address(proxy));
        token.mint(address(wallet), WALLET_BALANCE);

        // Non-vacuous: legit owner op via plain call.
        vm.prank(OWNER);
        wallet.execute(
            address(token), 0, abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT, LEGIT_XFER)
        );
        assertEq(token.balanceOf(RECIPIENT), LEGIT_XFER, "legit owner op executes");

        // (a) Attacker tries to redirect the delegatecall sink via an upgrade -> owner-gated, reverts.
        EvilUpgradeImpl evil = new EvilUpgradeImpl();
        vm.prank(ATTACKER);
        vm.expectRevert(bytes("not owner"));
        wallet.upgradeToAndCall(
            address(evil), abi.encodeWithSignature("sweep(address,address)", address(token), ATTACKER)
        );

        // (b) Owner routes an op to a storage-takeover probe; runs via plain `call` in its own ctx.
        WalletTakeoverProbe probe = new WalletTakeoverProbe();
        vm.prank(OWNER);
        wallet.execute(address(probe), 0, abi.encodeWithSignature("hijack(address)", ATTACKER));

        bool hijacked = (wallet.owner() != OWNER) || (wallet.version() != 1)
            || (token.balanceOf(address(wallet)) != WALLET_BALANCE - LEGIT_XFER);
        _report("solady-uups-proxy-safe", hijacked);

        assertFalse(hijacked, "Solady UUPS proxy delegatecalls only its managed impl; no hijack");
        assertEq(wallet.owner(), OWNER, "wallet owner unchanged");
        assertEq(wallet.version(), 1, "implementation (delegatecall target) unchanged");
        assertEq(probe.owner(), ATTACKER, "the takeover write landed in the probe's own storage");
    }

    /// @notice OpenZeppelin TRANSPARENT-proxy admin pattern: upgrades are routed through an
    ///         external ProxyAdmin owned by the governance owner; non-admin callers are
    ///         delegatecalled to the logic. The delegatecall sink is the managed impl only and
    ///         cannot be redirected except by the ProxyAdmin owner. A different proxy mechanism
    ///         than the bare ERC1967/UUPS fixtures.
    function test_ozTransparentProxy_delegatecallTargetIsManaged_noHijack() public {
        // ERC-1967 admin storage slot: uint256(keccak256("eip1967.proxy.admin")) - 1.
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

        MockERC20 token = new MockERC20();
        TUPWallet impl = new TUPWallet();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), OWNER, abi.encodeCall(TUPWallet.initialize, (OWNER))
        );
        TUPWallet wallet = TUPWallet(address(proxy));
        token.mint(address(wallet), WALLET_BALANCE);

        address admin = address(uint160(uint256(vm.load(address(proxy), adminSlot))));

        // Non-vacuous: legit owner op via plain call (OWNER is a non-admin caller -> forwarded
        // to the logic).
        vm.prank(OWNER);
        wallet.execute(
            address(token), 0, abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT, LEGIT_XFER)
        );
        assertEq(token.balanceOf(RECIPIENT), LEGIT_XFER, "legit owner op executes");

        EvilUpgradeImpl evil = new EvilUpgradeImpl();

        // (a) Attacker upgrades via the proxy directly: a non-admin caller is delegatecalled to
        //     the logic, which has no `upgradeToAndCall` -> reverts.
        vm.prank(ATTACKER);
        (bool okViaProxy,) = address(proxy).call(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(evil), "")
        );
        assertFalse(okViaProxy, "non-admin upgrade via the proxy must fail");

        // (b) Attacker upgrades via the ProxyAdmin -> onlyOwner -> reverts.
        vm.prank(ATTACKER);
        (bool okViaAdmin,) = admin.call(
            abi.encodeWithSignature(
                "upgradeAndCall(address,address,bytes)", address(proxy), address(evil), ""
            )
        );
        assertFalse(okViaAdmin, "non-owner upgrade via the ProxyAdmin must fail");

        // (c) Owner routes an op to a storage-takeover probe; runs via plain `call`.
        WalletTakeoverProbe probe = new WalletTakeoverProbe();
        vm.prank(OWNER);
        wallet.execute(address(probe), 0, abi.encodeWithSignature("hijack(address)", ATTACKER));

        bool hijacked = (wallet.owner() != OWNER) || (wallet.version() != 1)
            || (token.balanceOf(address(wallet)) != WALLET_BALANCE - LEGIT_XFER);
        _report("oz-transparent-proxy-safe", hijacked);

        assertFalse(hijacked, "transparent proxy delegatecalls only its managed impl; no hijack");
        assertEq(probe.owner(), ATTACKER, "the takeover write landed in the probe's own storage");

        // Non-vacuous upgrade: the owner, via the ProxyAdmin, upgrades to V2 -> it applies.
        TUPWalletV2 implV2 = new TUPWalletV2();
        vm.prank(OWNER);
        ProxyAdmin(admin).upgradeAndCall(ITransparentUpgradeableProxy(address(proxy)), address(implV2), "");
        TUPWalletV2(address(proxy)).bump();
        assertEq(TUPWalletV2(address(proxy)).version(), 2, "legit admin-routed upgrade applies");
    }
}
