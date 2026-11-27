Fixture:      blind-eth-sign/b-incident/ethsign-blind-victim
Vector:       blind-eth-sign
Tier:         b-incident
Expected:     vuln

Origin:       The legacy eth_sign path signs an opaque 32-byte hash with no displayable
              structure; drainers used it to obtain blind authorizations that replay as transfers.
Reference:    MetaMask MIP-3 (accepted 2024-05-15) removed eth_sign (Aug 2024) citing blind-
              signing phishing risk; Safe removed eth_sign days after the Bybit hack (2025-02);
              the Ethereum Foundation launched Clear Signing (ERC-7730) in response. Onchain Diary
              "ETH sign Phishing Explained"; Scam Sniffer drainer analyses.
Source code:  toy + reference-impl authored in this repo (MIT); no third-party code copied.
License:      MIT (this repo).

Minimization: BlindSigWallet recovers the signer from a raw attacker-chosen hash and executes the
              hidden transfer; the victim signs that bare hash (vm.sign over the raw digest, no
              prefix, no struct), modeling eth_sign blind signing.
Offline:      Fully offline; no live RPC. Deterministic Foundry test in Docker.
Notes:        Distinct from signature-phishing (EIP-712 typed Seaport orders): the defect here is
              signing an UNSTRUCTURED, UNDISPLAYABLE hash. Proof level: class-level, and it stays
              class-level by design. A search for a single clean, citable on-chain transaction
              that isolates a raw `eth_sign` (bare 32-byte hash) drain did not yield a verified
              hash: `eth_sign` is an off-chain signing operation, so on-chain only the downstream
              consumption of the signature is visible and is not reliably distinguishable from a
              typed/permit signature at the transaction level. We therefore cite the mechanism and
              its deprecation rather than inventing a tx: MetaMask MIP-3 (accepted 2024-05-15)
              removed `eth_sign` citing blind-signing phishing; Safe removed `eth_sign` within
              days of the Bybit hack; the EF launched Clear Signing (ERC-7730). Harness MUST flag
              VULNERABLE.
