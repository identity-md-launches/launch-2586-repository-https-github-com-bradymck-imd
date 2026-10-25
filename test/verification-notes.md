# Verifier test delivery

Only tests, test fixtures and their offline generation dependencies were changed. The existing
`make test` target discovers every new suite. No production contract, ABI, configuration,
Makefile, deployment file, reward contract or registry was changed.

## Checks

```sh
forge build --offline
FOUNDRY_FUZZ_SEED=0x4c3111c9d3cbce64ad39b508ac8cae717b41638c104f0bc6799e8fe01c04de0a forge test --offline -vv
```

The required encoding fuzz test retains its inline **10,000 runs**. Modified signatures use
2,000 runs, and malformed duplicate lengths use 1,000 runs. Input construction excludes the
original round without `vm.assume`. The invariant campaign uses **128 runs × 64 calls**, with
`fail-on-revert = true`, and targets only the handler's six action selectors. Expected contract
reverts are checked inside the handler; assertion failures cannot be silently discarded.
Deterministic handler tests demonstrate first writes, duplicates, early failures, authorization
failures, successful retries, and valid publications at bitmap word boundaries.

The independent oracle coverage is now RFC 9380 + noble + blst. Blst reproduced all 109 original
signatures and added six bitmap-boundary signatures. Its offline generator also checks every
threshold subset and all five RFC hash-to-curve points. Provenance, source/wheel hashes and
licences are under `test/vectors`. No successful signature test mocks cryptography. Precompile
mocks inject failures; the single zero-randomness test mocks only the final output hash, then
exercises real storage, the event, and duplicate handling with a zero value.

## Discovery passes and properties

The supplied Pashov fizz and Trail of Bits references were used as background for these five
manual passes; no subagents or external fuzz engines were used. The properties below are
backed by SPEC §§4.3, 8.2, 8.3 and 10.3.

| Pass | Candidate property and evidence in code | Coverage |
|---|---|---|
| Conservation | Distinct stored rounds equal successful first writes; one publication event per first write. Storage is `_values` / `_available` (`BeaconVerifier.sol:75,77`), writes/event at lines 144–146. | Handler keeps an independent per-round publication history and checks values, availability, event topics/data, and counts after each sequence step. There is no ETH/token/reward accounting in Job 2. |
| State transitions | Only released, authorized valid rounds become available; failed calls leave neighboring rounds untouched (`submit`, lines 124–147). Matching duplicates do not write/emit. | Stateful handler, explicit atomicity tests, exact storage-access checks, epoch/missing-authority failures and retries. |
| Round trips and rounding | `roundAt(t)` selects the earliest release at or after t; adjacent rounds differ by 30 seconds; epoch boundaries and uint64 limits are correct (lines 173–191). Compression agrees with independent encoders. | Stateless fuzz properties assert ordering/minimality, plus exact genesis, epoch, last-round, and overflow cases. |
| Adversarial calls | Malformed coordinates and signatures, missing/short/oversized/reverting precompiles, and non-one pairing results fail closed. Genesis checks expected outputs (constructor lines 84–113). | Adversarial suite covers every required precompile, each G2 coefficient/padding region, output SHA return length, dependency failure atomicity, and bounded gas on non-subgroup failure. The duplicate off-curve defect is reported separately. |
| Protocol-specific | Permissionless unchained relay, no caller/receiving-chain/time dependence in pure verification, pinned descriptor/key, network/epoch domain separation and bitmap isolation. | Competing relayers, cross-chain-id checks, different-key/network fixtures, independent history invariant over 20 rounds including sparse/high/last rounds and bits 0, 1, 255 across bitmap words. |

The handler never writes verifier storage directly. Its expected epochs and release times come
from independent fixtures. Authorization is a test-only stand-in for the later registry job.
New economic invariants were not invented for the out-of-scope reward system.

## Gas measurements

Measured with forge 1.8.3 (`cae51ad`), solc 0.8.30, optimizer enabled / 200 runs, no via-IR,
Prague, `bytecode_hash = none`, and the fixed repository profile. These match the existing
`docs/verification-gas.md`. The caller warms the verifier account before measuring execution.
Receipt estimates include 21,000 intrinsic gas and actual ABI calldata byte costs, as well as
external-call overhead. They are local EVM measurements, not live-chain receipts.

| Case | Execution gas | Calldata gas | Receipt gas | Budget |
|---|---:|---:|---:|---:|
| Verify round 17 | 135,374 | n/a | n/a | 170,000 execution |
| First publication, zero availability word | 207,393 | 2,008 | 230,401 | 250,000 receipt |
| First publication, nonzero availability word | 190,294 | 2,008 | 213,302 | 250,000 receipt |
| First publication with epoch gate | 212,926 | 2,020 | 235,946 | 250,000 receipt |

A nonzero first publication writes exactly the value mapping slot and one availability word;
a matching duplicate writes no slots and emits no event. The explicit storage-access tests
check this. The descriptor/key remain immutable code data. Rewards are excluded.

## Reported implementation defect

A medium-severity finding and a complete, reproduced failing Foundry proof are recorded in
`.imd-findings.json` at the repository root, using the assignment's reporting exception.
`BeaconVerifier.submit` lines 130–136 compresses an already-published round's supplied affine
signature without checking its curve equation. Flip bit 0 of byte 95 of the round-1 fixture:
`verify` rejects it, while duplicate `submit` accepts it because x and the compression sign
bit are unchanged. Expected behavior is rejection on both paths (SPEC §4.3).

The invalid duplicate returns false, does not change the stored value, and does not emit a
second event; no randomness replacement or second fee is demonstrated. The test suite does
not assert that accepting it is correct. The failing proof belongs in the report rather than
the passing suite. To replay, save its `proof` source as
`test/scratch/DuplicateOffCurveProof.t.sol` and run:

```sh
forge test --offline --remappings forge-std/=test/forge-std/src/ --match-path test/scratch/DuplicateOffCurveProof.t.sol -vv
```

The CLI remapping is necessary because the existing forge-std files live under `test/`,
without a project-level remapping. The proof imports only `forge-std/Test.sol` and the
production verifier, uses inline public NON-PRODUCTION fixtures, and fails at the final
`submit` expectation on the current implementation. Replaying it is expected to fail until
the production defect is repaired.

## Scope and specification differences

The assignment's test-only path restriction takes precedence over its broader Job 2 file
list; the accepted production implementation was left intact. SPEC §10.3 explicitly names
blst while the inherited suite provided noble alone: this test gap is closed with the new
blst cross-check. The accepted implementation's handwritten libraries are under `src/bls/`
rather than the `lib/` delivery path in the Job 2 description. This placement difference is
recorded here without relocating or claiming to externally audit those production files.
