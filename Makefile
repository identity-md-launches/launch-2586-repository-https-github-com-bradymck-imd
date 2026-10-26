# imd-beacon offline checks (SPEC §10.3: each job supplies an offline command here).
# Nothing below needs the network: forge-std and the vectors are committed as ordinary files.

FORGE ?= forge
# The seed IMD's verifier uses for this job's fuzz tests; override with FUZZ_SEED=0x...
FUZZ_SEED ?= 0x21a72a54ac22fd21b2fa321a6c0150026794b2a2d1dbbd5357facdd14b61c6ad

export FOUNDRY_OFFLINE = true

.PHONY: build test test-verifier gas vectors

build:
	$(FORGE) build

## Whole suite, offline, with the pinned fuzz seed (10,000-run fuzz tests included).
test:
	FOUNDRY_FUZZ_SEED=$(FUZZ_SEED) $(FORGE) test

## Job 2 only: the verifier tests with gas logs (docs/verification-gas.md).
test-verifier:
	FOUNDRY_FUZZ_SEED=$(FUZZ_SEED) $(FORGE) test --match-path test/contracts/BeaconVerifier.t.sol -vv

gas:
	$(FORGE) test --match-test "testGas_" -vv

## Regenerates test/vectors/bls12.json with the independent implementation (needs node and a
## local copy of @noble/curves; see scripts/gen_bls12_vectors.mjs). Not needed for the tests.
vectors:
	node scripts/gen_bls12_vectors.mjs $(RFC9380_TXT)
