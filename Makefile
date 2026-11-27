# wallet-harness - convenience entry points. Everything runs offline in Docker;
# Foundry runs inside the container, so you only need Docker + git.
.PHONY: help doctor forge-std run benchmark ctf selftest bench

help:
	@echo "wallet-harness - make targets:"
	@echo "  make doctor     check prerequisites (Docker daemon, forge-std)"
	@echo "  make forge-std  clone the pinned forge-std build dependency into lib/"
	@echo "  make run        run the corpus vectors in Docker, print a verdict per target"
	@echo "  make benchmark  run EVERY labeled fixture in Docker -> confusion matrix + p/r/F1"
	@echo "  make bench      score the bundled wal result instantly (no Docker re-run)"
	@echo "  make ctf        list the CTF challenges (then: ./ctf/ctf.sh start <name>)"
	@echo "  make selftest   CTF ground-truth check (seed->FAIL, solution->PASS, in Docker)"
	@echo ""
	@echo "  bench vs benchmark: 'bench' scores the committed verdicts (fast, offline);"
	@echo "  'benchmark' re-runs the dynamic Foundry harness to regenerate them (needs Docker)."
	@echo ""
	@echo "Score your own detector:  bench/score.sh --template > my.txt   # fill in verdicts"
	@echo "                          bench/score.sh my.txt                # confusion matrix + p/r/F1"
	@echo "Any script also takes --help."

doctor:
	@./ctf/ctf.sh doctor

forge-std:
	@test -f lib/forge-std/src/Test.sol \
	  || git clone --depth 1 --branch v1.9.4 https://github.com/foundry-rs/forge-std lib/forge-std

ctf:
	@./ctf/ctf.sh list

selftest:
	@./ctf/ctf.sh selftest

run:
	@./harness/run.sh

benchmark:
	@./harness/benchmark.sh

bench:
	@bench/score.sh bench/results/wal/verdicts.txt
