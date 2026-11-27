# Provenance - upgrade-governance tier (c): `oz-timelock-safe`

Genuinely-safe REAL code for vector `upgrade-governance` (R10′). The harness must stay
silent on it (label **safe** -> verdict **BLOCKED**, 0 false positives).

## Safety-relevant code = unmodified OpenZeppelin
- **Source:** https://github.com/OpenZeppelin/openzeppelin-contracts
- **Tag / commit:** `v5.1.0` / `69c8def5f222ff96f2b5beff05dfba996368aa79`
- **License:** MIT - full text in [`../../../vendor/oz/LICENSE`](../../../vendor/oz/LICENSE);
  vendoring summary in [`../../../vendor/PROVENANCE.md`](../../../vendor/PROVENANCE.md).
- **Vendored byte-for-byte** (import closure of the two primitives below, each keeping its
  original SPDX line and OpenZeppelin header; nothing modified):
  - `proxy/utils/UUPSUpgradeable.sol` (+ `proxy/ERC1967/ERC1967Utils.sol`,
    `proxy/ERC1967/ERC1967Proxy.sol`, `proxy/Proxy.sol`, `proxy/beacon/IBeacon.sol`,
    `interfaces/IERC1967.sol`, `interfaces/draft-IERC1822.sol`, `utils/Address.sol`,
    `utils/Errors.sol`, and the already-vendored `utils/StorageSlot.sol`).
  - `governance/TimelockController.sol` (+ `access/AccessControl.sol`,
    `access/IAccessControl.sol`, `token/ERC721/utils/ERC721Holder.sol`,
    `token/ERC1155/utils/ERC1155Holder.sol`, `token/ERC1155/IERC1155Receiver.sol`, and the
    already-vendored `utils/Context.sol`, `utils/introspection/{ERC165,IERC165}.sol`,
    `token/ERC721/IERC721Receiver.sol`).

## What is authored here (the thin wrapper)
Only `OZTimelockUUPSWallet.sol` is written in this repo on top of the unmodified OZ base. It
adds a one-shot `initialize(upgradeAuthority)` and the UUPS `_authorizeUpgrade` override that
gates the upgrade on the authority. It adds **no bespoke delay/guardian logic** - the
delay + role gating comes entirely from the real OZ `TimelockController`, which is the
wallet's upgrade authority.

## Why this proves the rule stays silent on safe code
R10′ fires on a single-key, no-delay implementation/module swap. Here:
- the UUPS `upgradeToAndCall` is gated by `_authorizeUpgrade` on the `TimelockController`
  (not an EOA), so a direct instant swap by any single key reverts; and
- the only path to an upgrade is `TimelockController.schedule` -> wait `minDelay` ->
  `execute`, a role-gated, time-locked governance action.

The test (`test/RealSafeUpgradeGovernance.t.sol`) shows the instant attacker swap reverts
(wallet never drained -> BLOCKED) and that a legitimate, timelock-scheduled upgrade still
applies after the delay (BLOCKED is not vacuous). Offline, deterministic, no network/live
contracts.
