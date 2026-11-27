# wallet-harness CTF - "patch the drain"

A small capture-the-flag layer on top of the frozen drain corpus. Each challenge hands you
a **deliberately vulnerable** wallet contract built from one of the corpus's drain vectors.
Your job is to **patch the hole** without breaking what the contract is for.

This is additive: it reuses the vectors the benchmark already proves, but turns each one
into a hands-on exercise. Nothing here changes the benchmark or the fixtures.

## Why the gate has two sides

A hidden exploit test (the *gate*) grades your fix on **two** things at once:

- **security** - the drain exploit no longer empties the wallet, and
- **functionality** - the legitimate operation the contract exists for still works.

You pass only when **both** hold. This matters: the cheap "fix" for almost any drain is to
delete the feature (approve nothing, transfer to nobody). That stops the exploit but bricks
the contract - and the gate fails you for it. Likewise, leaving the hole open fails the
security side. It's the same bar the benchmark enforces - *catch the vector on the
vulnerable side, stay correct on the safe side* - recast as a puzzle you solve by editing
code.

## Play

```bash
ctf/ctf.sh doctor                   # check prerequisites (Docker daemon, forge-std)
ctf/ctf.sh list                     # see the challenges ( - unsolved / ✓ solved, + a solved N/total count )
ctf/ctf.sh start approve-drainer     # seed a work copy you edit
#   -> edit ctf/work/approve-drainer/src/Challenge.sol
ctf/ctf.sh solve approve-drainer     # run the hidden gate (Docker) against your copy
ctf/ctf.sh hint  approve-drainer     # just the hint from the brief
ctf/ctf.sh diff  approve-drainer     # what you changed vs the vulnerable seed
ctf/ctf.sh reset approve-drainer     # throw your copy away and start over
```

(`solve` prints a two-sided `GATE: security / functionality` summary and, on success, points
to the mechanism and the reference fix. `list` tracks your progress locally - `-`/`✓` and a
`solved N/total` count - ordered intro -> core -> advanced.)

`start` prints the brief and drops an editable copy of the vulnerable contract at
`ctf/work/<challenge>/src/Challenge.sol`. Edit only that file - keep the function signature
the brief gives you, since the gate calls it by name. `solve` runs the gate in Docker and
tells you SOLVED / NOT SOLVED with a per-check (`security` / `functionality`) line.

## How a challenge is built

```
ctf/challenges/<name>/
  meta              # vector, title, difficulty, the stable interface the gate calls
  prompt.md         # the brief shown by `start`
  seed/Challenge.sol      # the vulnerable contract you edit
  solution/Challenge.sol  # reference fix (SPOILER) - also the self-test's ground truth
  hidden/Exploit.t.sol    # the gate: a Foundry test asserting security + functionality
  hidden/Harness.sol      # self-contained test doubles (mock token, attacker)
```

Each challenge is self-contained: the gate compiles only `Challenge.sol`, the exploit test,
and its mocks - no dependency on the main `src/` tree.

## Self-test (ground truth)

A challenge is only well-formed if its gate **rejects the vulnerable seed** and **accepts
the reference solution** - the CTF analog of the benchmark's vuln/safe pair:

```bash
ctf/ctf.sh selftest            # all challenges
ctf/ctf.sh selftest <name>     # one
```

## Requirements & border

- Docker + `ghcr.io/foundry-rs/foundry:stable`, and `lib/forge-std` in the repo (see the
  top-level README for the pinned clone command). The runner respects the shared-VM cap of
  3 containers.
- These contracts are intentionally vulnerable **toys**. Never deploy them anywhere. The
  gate runs entirely offline in Docker.
