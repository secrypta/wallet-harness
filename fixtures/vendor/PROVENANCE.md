# Vendored third-party source - provenance

## OpenZeppelin Contracts (`oz/`)
- **Source:** https://github.com/OpenZeppelin/openzeppelin-contracts
- **Tag:** `v5.1.0`
- **Commit:** `69c8def5f222ff96f2b5beff05dfba996368aa79`
- **License:** MIT - full text in [`oz/LICENSE`](oz/LICENSE) (Copyright (c) 2016-2024
  Zeppelin Group Ltd).
- **Scope:** only the dependency closure needed to compile a concrete ERC-20, ERC-721 and
  EIP-2612 `ERC20Permit` (token + the `utils`/`interfaces`/`introspection`/`cryptography`
  files they import). Files are vendored **byte-identical** to the tagged release, each
  keeping its original SPDX line and OpenZeppelin header, so the attribution and license
  travel with the code. Nothing in `oz/` is modified.
- **ERC20Permit closure (added):** `token/ERC20/extensions/ERC20Permit.sol`,
  `token/ERC20/extensions/IERC20Permit.sol`, `utils/cryptography/EIP712.sol`,
  `utils/cryptography/ECDSA.sol`, `utils/cryptography/MessageHashUtils.sol`,
  `utils/Nonces.sol`, `utils/ShortStrings.sol`, `utils/StorageSlot.sol`,
  `interfaces/IERC5267.sol`.
- **UUPS + TimelockController closure (added):** the import closure needed to compile a
  timelock-governed UUPS upgrade (tier (c) of `upgrade-governance`), vendored byte-identical:
  `proxy/utils/UUPSUpgradeable.sol`, `proxy/ERC1967/ERC1967Proxy.sol`,
  `proxy/ERC1967/ERC1967Utils.sol`, `proxy/Proxy.sol`, `proxy/beacon/IBeacon.sol`,
  `interfaces/IERC1967.sol`, `interfaces/draft-IERC1822.sol`, `utils/Address.sol`,
  `utils/Errors.sol`, `governance/TimelockController.sol`, `access/AccessControl.sol`,
  `access/IAccessControl.sol`, `token/ERC721/utils/ERC721Holder.sol`,
  `token/ERC1155/utils/ERC1155Holder.sol`, `token/ERC1155/IERC1155Receiver.sol`
  (reusing the already-vendored `utils/StorageSlot.sol`, `utils/Context.sol`,
  `utils/introspection/{ERC165,IERC165}.sol`, `token/ERC721/IERC721Receiver.sol`).

## Why vendored (not a submodule / lib dependency)
The validation standard ([`corpus/real-cases.md`](../../corpus/real-cases.md))
requires the real-safe tier (c) to run against *genuinely
real* code, committed and deterministic (no network dependency in CI). Vendoring the exact
tagged OZ source as committed fixtures satisfies that: the safety-relevant logic
exercised by tier (c) - ERC-20 allowance accounting and ERC-721 `transferFrom`
authorization - is unmodified OpenZeppelin, not a lightly-edited toy.

## Consumers (tier (c) real-safe fixtures)
- `fixtures/approve-drainer/c-safe-impl/` - concrete OZ ERC-20 + a bounded-approve wallet
  policy. Expected label: **safe** (harness verdict **BLOCKED**).
- `fixtures/set-approval-for-all/c-safe-impl/` - concrete OZ ERC-721 + a scoped-approve
  wallet policy. Expected label: **safe** (harness verdict **BLOCKED**).
- `fixtures/permit-phishing/c-safe-impl/oz-permit-safe/` - concrete OZ ERC20Permit (EIP-2612)
  + a bounded-permit flow. Expected label: **safe** (harness verdict **BLOCKED**).
- `fixtures/upgrade-governance/c-safe-impl/oz-timelock-safe/` - a UUPS-upgradeable wallet
  whose upgrade authority is an OZ `TimelockController` (real UUPS + timelock). Expected
  label: **safe** (harness verdict **BLOCKED**).

Each fixture *entry* file (the concrete token subclass and the wallet-policy contract)
carries its own provenance block in-file; those are the only files authored here on top of
the unmodified OZ base, and they add only a test-only `mint` entrypoint plus the defensive
approval policy under test.

---

## Uniswap Permit2 (`permit2/`)
- **Source:** https://github.com/Uniswap/permit2
- **Commit:** `cc56ad0f3439c502c246fc5cfcc3db92bb8b7219` (copied 2026-11-13)
- **License:** MIT - Copyright (c) 2022 Uniswap Labs - full text in
  [`permit2/LICENSE`](permit2/LICENSE).
- **Pragma:** Permit2 pins an **exact** `pragma solidity 0.8.17`. The repo's `foundry.toml`
  uses `auto_detect_solc = true` so Permit2 compiles at 0.8.17 and links at the bytecode
  level alongside our 0.8.24 sources and OZ's ^0.8.20.
- **Scope (import closure of `Permit2.sol`, vendored byte-for-byte):**
  `src/Permit2.sol`, `src/AllowanceTransfer.sol`, `src/SignatureTransfer.sol`,
  `src/EIP712.sol`, `src/PermitErrors.sol`,
  `src/interfaces/{IAllowanceTransfer,ISignatureTransfer,IEIP712,IERC1271}.sol`,
  `src/libraries/{Allowance,PermitHash,SignatureVerification,SafeCast160}.sol`.
  (Integrator-only files `Permit2Lib.sol`, `interfaces/IPermit2.sol`,
  `interfaces/IDAIPermit.sol` are outside this closure and not vendored.)
- **Documented deviation (owner decision: Variant C) - the ONLY change to Permit2 source:**
  the real Permit2 transitively depends on **solmate** (`ERC20.sol`, `SafeTransferLib.sol`),
  which is **AGPL-3.0-only** and would taint this MIT repo. To keep the repo pure MIT, the
  two solmate `import` lines (in `AllowanceTransfer.sol` and `SignatureTransfer.sol`) were
  repointed to an **MIT shim** in `permit2/mit-shim/` (`ERC20.sol`, `SafeTransferLib.sol`)
  exposing the identical API Permit2's core uses - the `ERC20` token type and
  `safeTransferFrom(ERC20, address, address, uint256)`. **Only those two import lines
  differ** from upstream; the diff is limited to them. Permit2's defensive logic
  (allowance accounting, EIP-712 signature verification, nonce/expiration) is **untouched**.
  solmate's AGPL source is **not** copied into this repo.

### Consumer (tier (c) real-safe fixture)
- `fixtures/permit2-phishing/c-safe-impl/scoped-permit2-safe/` - the real vendored Permit2
  under a scoped-signature policy, with an MIT `Permit2SafeToken` vehicle. Expected label:
  **safe** (harness verdict **BLOCKED**).

---

## Solady (`solady/`)
- **Source:** https://github.com/Vectorized/solady
- **Tag:** `v0.1.22`
- **Commit:** `65e87c72a5ee4a6708946b25611ec5f980ceba70` (copied 2026-11-14)
- **License:** MIT - Copyright (c) 2022-2025 Solady - full text in [`solady/LICENSE`](solady/LICENSE).
- **Scope:** vendored **byte-identical**, except the one documented import-path repoint below:
  - `src/tokens/ERC20.sol` - ERC-20 allowance accounting + EIP-2612 `permit` (self-contained).
  - `src/tokens/ERC721.sol` - ERC-721 operator / per-token authorization (self-contained).
  - `src/tokens/ERC6909.sol` - EIP-6909 multi-token per-id allowance + operator (self-contained;
    no imports). sha256 `95a71e603f48e503a9d2c386de4c2760d8f15830b08a1461c7caaa47481c34db`.
  - `src/accounts/ERC1271.sol` - ERC-1271 / ERC-7739 nested-EIP-712 signature verification.
  - `src/utils/EIP712.sol`, `src/utils/SignatureCheckerLib.sol` - the ERC1271 import closure.
- **Documented deviation (import-only, the ONLY change):** upstream `ERC1271.sol` imports
  `../utils/EIP712.sol` and `../utils/SignatureCheckerLib.sol`; here all three files live in
  one `solady/` dir, so those two import paths are repointed to `./EIP712.sol` and
  `./SignatureCheckerLib.sol`. **Only those two import lines differ**; the signature-verification
  logic is untouched. (Same kind of import-only repoint already documented for Permit2 above.)
- **Why a second, independent safe codebase:** the OZ and Permit2 tier-(c) fixtures prove the
  harness stays silent on *our chosen* canonical code. Adding Solady - a **different**,
  independent implementation the wal detectors were **never tuned against** - turns that into a
  genuine **holdout precision** test: the detectors must also stay silent on unseen real safe
  code. If they did not, that false positive is a real, recorded result.

### Consumers (tier (c) real-safe **holdout** fixtures, `split=holdout`)
- `fixtures/approve-drainer/c-safe-impl/solady-erc20-safe/` - bounded `approve` on the
  unmodified Solady ERC20; over-draw reverts. Expected label: **safe** (**BLOCKED**).
- `fixtures/permit-phishing/c-safe-impl/solady-permit-safe/` - a forged EIP-2612 permit is
  rejected by Solady's signature check. Expected label: **safe** (**BLOCKED**).
- `fixtures/approve-drainer/c-safe-impl/solady-erc6909-safe/` - a bounded per-token-id allowance
  on the unmodified Solady ERC6909 cannot be over-drawn (transferFrom reverts
  InsufficientPermission). Expected label: **safe** (**BLOCKED**).
- `fixtures/approve-drainer/c-safe-impl/solady-erc4626-safe/` - a bounded approve on Solady
  ERC4626 vault shares (the share token is a Solady ERC20) cannot be over-drawn. Expected label:
  **safe** (**BLOCKED**).
- `fixtures/signature-phishing/c-safe-impl/solady-erc1271-safe/` - a forged signature is rejected
  by Solady's ERC-1271 / ERC-7739 verification; a signature-gated withdrawal cannot proceed.
  Expected label: **safe** (**BLOCKED**).
- `fixtures/set-approval-for-all/c-safe-impl/solady-erc721-safe/` - a scoped single-token approval
  on Solady ERC721 does not let an operator sweep the holder's other tokens. Expected label:
  **safe** (**BLOCKED**).

The concrete vehicles (`SoladyERC20Fixture.sol`, `SoladyERC721Fixture.sol` and
`SoladyERC1271Fixture.sol` under the respective c-safe-impl dirs) add only the required override
hooks (metadata getters / `_erc1271Signer`) plus a test-only `mint` or a signature-gated
`withdraw` on top of the unmodified Solady base; the allowance / operator-authorization / permit /
signature-verification logic exercised by the fixtures is untouched Solady.

---

## Solady - account-abstraction stack (`solady-accounts/`)
- **Source:** https://github.com/Vectorized/solady
- **Tag:** `v0.1.22`
- **Commit:** `65e87c72a5ee4a6708946b25611ec5f980ceba70` (copied 2026-11-14)
- **License:** MIT - Copyright (c) 2022-2025 Solady - same license as `solady/` (see
  [`solady/LICENSE`](solady/LICENSE)).
- **Why a separate tree from `solady/`:** the `solady/` dir above is *flattened* (all files in
  one directory, with two documented import-path repoints). This `solady-accounts/` tree instead
  mirrors Solady's upstream `src/` layout **exactly** (`accounts/`, `auth/`, `utils/`), so every
  `import` resolves unchanged - the files are **byte-identical to the tagged release with zero
  modifications** (no repoints, no edits). It is a pristine, independent real-code corpus for the
  0-FP probe (`drain-scan/validate/zero_fp_probe.py`).
- **Why these contracts:** they are canonical **smart-wallet / account** implementations - the
  exact surface drain-scan's rules target - so staying silent on them is a genuine precision
  result. Covers ERC-4337 (`ERC4337`, `ERC4337Factory`), ERC-6551 token-bound accounts
  (`ERC6551`), ERC-7821 batch execution (`ERC7821`), a role/ownable-gated `Timelock`, UUPS
  upgradeability (`UUPSUpgradeable` + `CallContextChecker`) and ERC-1271/ERC-7739 signature
  verification (`ERC1271`). This stresses R1-R11 (approvals, signatures, upgrade authority,
  delegation/batch-call) on real audited code the detectors were never tuned against.
- **Scope (import closure, vendored byte-for-byte):**
  `accounts/{ERC4337,ERC4337Factory,ERC6551,ERC7821,Receiver,ERC1271,LibERC7579,Timelock}.sol`,
  `auth/{Ownable,OwnableRoles,EnumerableRoles}.sol`,
  `utils/{UUPSUpgradeable,CallContextChecker,LibZip,EIP712,SignatureCheckerLib,LibClone}.sol`,
  plus a second independent-utility batch (standalone):
  `tokens/{ERC20,ERC2981,ERC4626}.sol`,
  `utils/{SafeTransferLib,Multicallable,ReentrancyGuard,MerkleProofLib,FixedPointMathLib,MetadataReaderLib}.sol`
  (`ERC4626` imports the sibling `ERC20` + `SafeTransferLib`/`FixedPointMathLib`; see the ERC-4626
  precision note below).
  (Upstream `accounts/EIP7702Proxy.sol` is **not** vendored: it uses transient storage
  (`tload`/`tstore`), which needs `--evm-version cancun`; the pinned probe compiler runs the
  default EVM target, so it would be a spurious "uncompilable" note. Nothing in the closure
  imports it.) Each file keeps its original SPDX line and Solady header.

## OpenZeppelin - probe corpus expansion (`oz/`, same tag/commit)
Added to the existing `oz/` tree (still **byte-identical** to `v5.1.0` /
`69c8def5f222ff96f2b5beff05dfba996368aa79`, upstream layout, unmodified) to widen the 0-FP probe
with more real wallet/access/upgrade surface. Import closures of:
`proxy/utils/Initializable.sol`, `access/manager/AccessManager.sol` (+ `IAccessManaged`,
`IAccessManager`, `access/Ownable`, `utils/types/Time`), `metatx/ERC2771Context.sol`,
`utils/Multicall.sol`, `finance/VestingWallet.sol`,
`utils/cryptography/SignatureChecker.sol` (+ `interfaces/IERC1271`), and the supporting
interfaces/libs they pull (`token/ERC20/utils/SafeERC20.sol`, `interfaces/{IERC20,IERC165,IERC1363}.sol`).
A second batch widens the governance / voting / proxy / pausability surface:
`governance/Governor.sol` + extensions
(`GovernorSettings`, `GovernorCountingSimple`, `GovernorVotes`, `GovernorVotesQuorumFraction`,
`GovernorTimelockControl`) with `IGovernor` and `governance/utils/{IVotes,Votes}.sol`,
`token/ERC20/extensions/ERC20Votes.sol`, `proxy/Clones.sol`, `utils/Pausable.sol`,
`utils/ReentrancyGuard.sol`, and the structs they pull
(`utils/structs/{Checkpoints,DoubleEndedQueue}.sol`, `interfaces/{IERC5805,IERC6372}.sol`).
A third addition is the canonical ERC-4626 tokenized vault
(`token/ERC20/extensions/ERC4626.sol` + `interfaces/IERC4626.sol`).
A fourth addition (2026-11-17, same tag/commit, byte-identical, upstream layout) is the ERC-1155
operator-for-all closure - `token/ERC1155/{ERC1155,IERC1155}.sol`,
`token/ERC1155/extensions/IERC1155MetadataURI.sol`, `token/ERC1155/utils/ERC1155Utils.sol`,
`utils/{Arrays,Comparators,SlotDerivation}.sol` (reusing already-vendored
`token/ERC1155/IERC1155Receiver.sol`, `utils/Context`, `introspection/{ERC165,IERC165}`,
`math/Math`, `interfaces/draft-IERC6093.sol`) - consumed by the tier-(c) real-safe fixture
`fixtures/set-approval-for-all/c-safe-impl/oz-erc1155-safe/` (BLOCKED).
The earlier ERC-4626 files are consumed only by the 0-FP probe (no tier-(c) fixture depends on them).

## ERC-4626 - a worked precision example (now in the corpus)
Adding the real ERC-4626 vault (OpenZeppelin `token/ERC20/extensions/ERC4626.sol` and Solady
`tokens/ERC4626.sol`) first **surfaced a genuine false positive in rule R11**: it flagged
`ERC4626._deposit` - a `transferFrom(msg.sender, address(this), assets)` self-deposit that mints
shares back to the caller - as an arbitrary-callee standing-approval drain. The FP was **not**
path-suppressed; it was routed to the R11 owner and fixed by **narrowing R11** to ignore the
self-deposit pattern (`from == msg.sender && destination == address(this)`), with R11's true
positive on the real drainer fixture preserved. With that fix the vendored ERC4626 files are part
of the committed corpus and the probe is green on them. This is the broad-sweep probe doing
exactly its job: catching a precision gap on canonical audited code and driving a rule fix.

## Round-4 additions (2026-11-19, same tags/commits, byte-identical, upstream layout)
Four more files, each vendored **byte-identical** to the pinned release (OZ `v5.1.0` /
`69c8def5f222ff96f2b5beff05dfba996368aa79`; Solady `v0.1.22` /
`65e87c72a5ee4a6708946b25611ec5f980ceba70`), keeping its original SPDX line and header. Fetched
from the pinned commit's raw source; nothing modified (OZ files use relative imports that resolve
inside the mirrored `oz/` tree, so no repoint was needed).
- **`oz/utils/cryptography/MerkleProof.sol`** + its only import **`oz/utils/cryptography/Hashes.sol`**
  - OZ's canonical Merkle inclusion verifier. Consumed by the tier-(c) real-safe fixture
  `fixtures/fake-airdrop/c-safe-impl/oz-merkleproof-safe/` (a different canonical source than the
  existing Solady-`MerkleProofLib` holdout). Expected label **safe** (**BLOCKED**).
- **`oz/metatx/ERC2771Forwarder.sol`** - OZ's canonical EIP-712 meta-transaction forwarder
  (its import closure `ERC2771Context`, `ECDSA`, `EIP712`, `Nonces`, `Address`, `Errors` was
  already vendored). Consumed by `fixtures/signature-phishing/c-safe-impl/oz-erc2771-forwarder-safe/`
  - a forged `ForwardRequest` signature is rejected (`ERC2771ForwarderInvalidSigner`), so a relayed
  meta-tx cannot impersonate the victim. Expected label **safe** (**BLOCKED**).
- **`solady/ERC1155.sol`** - Solady's ERC-1155 (self-contained, no imports; sits in the flattened
  `solady/` dir alongside `ERC721.sol`). Consumed by
  `fixtures/set-approval-for-all/c-safe-impl/solady-erc1155-safe/` - an un-approved operator sweep
  reverts `NotOwnerNorApproved`. Expected label **safe** (**BLOCKED**).
  The `solady-accounts/auth/Ownable.sol` already in the pristine tree (unmodified) is additionally
  consumed by `fixtures/eip7702-delegation/c-safe-impl/solady-ownable-initguard-safe/`, whose thin
  7702-delegate vehicle overrides only `_guardInitializeOwner() => true` and adds an `initialize` /
  owner-gated `execute`; the initialization-hijack defense exercised (a re-`initialize` reverts
  `AlreadyInitialized`) is Solady's unmodified `_initializeOwner` / `_guardInitializeOwner` logic.

## Round-5 additions (2026-11-19, same tags/commits, byte-identical, upstream layout)
Three more files, each vendored **byte-identical** to the pinned release (OZ `v5.1.0` /
`69c8def5f222ff96f2b5beff05dfba996368aa79`; Solady `v0.1.22` /
`65e87c72a5ee4a6708946b25611ec5f980ceba70`), keeping its original SPDX line and header. Fetched
from the pinned commit's raw source and verified byte-identical against an already-vendored file
at the same tag before inclusion; nothing modified.
- **`oz/proxy/transparent/TransparentUpgradeableProxy.sol`** + **`oz/proxy/transparent/ProxyAdmin.sol`**
  - OZ's canonical transparent-proxy pattern (import closure `ERC1967Proxy`, `ERC1967Utils`,
  `IERC1967`, `access/Ownable` already vendored). Consumed by the tier-(c) real-safe fixture
  `fixtures/delegatecall-hijack/c-safe-impl/oz-transparent-proxy-safe/` - a different proxy
  mechanism than the bare ERC1967/UUPS holdout. Expected label **safe** (**BLOCKED**).
- **`solady-accounts/utils/CREATE3.sol`** - Solady's canonical CREATE3 deterministic deployer
  (self-contained, no imports; MIT, Solady copyright - a Solady reimplementation, not the
  AGPL Solmate original). Consumed by `fixtures/create2-metamorphic/c-safe-impl/solady-create3-safe/`
  - a code-independent deterministic address, distinct from the EIP-1167-clone holdouts. Expected
  label **safe** (**BLOCKED**).

## Round-6 additions (2026-11-19, byte-identical, upstream layout)

### ERC721A (`erc721a/`)
- **Source:** https://github.com/chiru-labs/ERC721A
- **Tag:** `v4.3.0`
- **Commit:** `6f8a82a7b2833ad8b2fc7b54349281143a731fdd`
- **License:** MIT - full text in [`erc721a/LICENSE`](erc721a/LICENSE) (Copyright (c) 2022
  Chiru Labs).
- **Scope:** `contracts/ERC721A.sol` + `contracts/IERC721A.sol` - the complete import closure
  (`ERC721A.sol` imports only `IERC721A.sol`, which is self-contained; `pragma ^0.8.4`). Both
  vendored **byte-identical** to the tagged release, keeping their original SPDX line and
  `ERC721A Contracts v4.3.0 / Creator: Chiru Labs` header. Checked out from the `v4.3.0` tag
  (distinct from the repo's `main` HEAD) and verified byte-identical (md5) against the tag before
  inclusion; nothing modified.
- **Consumer:** `fixtures/set-approval-for-all/c-safe-impl/erc721a-operator-safe/` - ERC721A is an
  INDEPENDENT third ERC-721 codebase (packed sequential ownership + batch mint) distinct from the
  OZ and Solady NFT holdouts, exercising the canonical `setApprovalForAll` operator-for-all
  authorization on real, widely-deployed wild code. Expected label **safe** (**BLOCKED**).

## Not vendored (deliberately - provenance discipline)
- **Canonical multisig wallet:** none vendored. OpenZeppelin removed its `MultiSigWallet` from
  current releases; Solady ships no multisig; the widely-used Safe (Gnosis Safe) contracts are
  **LGPL-3.0-only** (copyleft, incompatible with this MIT grant artifact - the same reason
  Permit2's AGPL solmate dependency was shimmed out) and pin `pragma 0.7.6` (outside the pinned
  0.8.x probe compilers). No MIT-clean, self-contained 0.8.x canonical multisig was found, so
  **none is included** rather than hand-rolling one - a synthetic "canonical" contract would be
  exactly the fabricated provenance this corpus forbids.
