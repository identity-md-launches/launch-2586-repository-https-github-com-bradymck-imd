# Verifier test delivery

Written for the test delivery of Job 2 and revised with the audit round 2 fixes
(`docs/reviews/job2-review.md`, "Audit round 2"; the fix record is `docs/reviews/job2-fixes.md`).
The fixes changed one production function, `BeaconVerifier.submit`'s duplicate path (finding 1);
the ABI, configuration, deployment files, reward contract and registry are unchanged. The
existing `make test` target discovers every suite.

## Checks

```sh
forge build --offline
FOUNDRY_FUZZ_SEED=0x21a72a54ac22fd21b2fa321a6c0150026794b2a2d1dbbd5357facdd14b61c6ad forge test --offline -vv
```

The required encoding fuzz test retains its inline **10,000 runs**; every run is adversarial and
checks the exact error on `verify`, on a first `submit` and on a duplicate `submit` after the
genuine signature was published. Modified signatures use 2,000 runs with the same three checks,
and malformed duplicate lengths use 1,000 runs. Input construction excludes the original round
without `vm.assume`. The invariant campaign uses **128 runs × 64 calls**, with
`fail-on-revert = true`, and targets only the handler's six action selectors. Expected contract
reverts are checked inside the handler against the exact revert data each state implies
(RoundNotReleased, EpochNotAuthorized, or the signature check's own error); assertion failures
cannot be silently discarded. Deterministic handler tests demonstrate first writes, duplicates,
early failures, authorization failures, successful retries, rejected inputs in every state, and
valid publications at bitmap word boundaries.

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
| State transitions | Only released, authorized valid rounds become available; failed calls leave neighboring rounds untouched (`submit`). Matching duplicates do not write/emit; any invalid duplicate reverts with the first-submission error. | Stateful handler, explicit atomicity tests, exact storage-access checks, epoch/missing-authority failures and retries, `test_DuplicateRejectsInvalidPoint`, `DuplicateOffCurveProof.t.sol`. |
| Round trips and rounding | `roundAt(t)` selects the earliest release at or after t; adjacent rounds differ by 30 seconds; epoch boundaries and uint64 limits are correct (lines 173–191). Compression agrees with independent encoders. | Stateless fuzz properties assert ordering/minimality, plus exact genesis, epoch, last-round, and overflow cases. |
| Adversarial calls | Malformed coordinates and signatures, missing/short/oversized/reverting precompiles, and non-one pairing results fail closed. Genesis checks expected outputs (constructor). | Adversarial suite covers every required precompile, each G2 coefficient/padding region, output SHA return length, dependency failure atomicity, and bounded gas on non-subgroup failure, each with its exact revert data. The duplicate off-curve defect is fixed and regression-tested (below). |
| Protocol-specific | Permissionless unchained relay, no caller/receiving-chain/time dependence in pure verification, pinned descriptor/key, network/epoch domain separation and bitmap isolation. | Competing relayers, cross-chain-id checks, different-key/network fixtures, independent history invariant over 20 rounds including sparse/high/last rounds and bits 0, 1, 255 across bitmap words. |

The handler never writes verifier storage directly. Its expected epochs and release times come
from independent fixtures. Authorization is a test-only stand-in for the later registry job.
New economic invariants were not invented for the out-of-scope reward system.

## Gas measurements

Measured with forge 1.8.5 (`51a52c5`), solc 0.8.30, optimizer enabled / 200 runs, no via-IR,
Prague, `bytecode_hash = none`, and the fixed repository profile. The gas tests run isolated
(each call is its own transaction) and read `vm.lastFrameGas().gasTotalUsed`, which for a
transaction includes 21,000 intrinsic gas and the actual ABI calldata byte costs; execution gas
is derived from it. `docs/verification-gas.md` explains the method and why the earlier numbers
(measured with `gasleft()` around an isolated call, then adding intrinsic and calldata gas again)
were overstated. They are local EVM measurements, not live-chain receipts.

| Case | Execution gas | Calldata gas | Receipt gas | Budget |
|---|---:|---:|---:|---:|
| Verify round 17 | 130,102 | n/a | n/a | 170,000 execution |
| First publication, zero availability word | 179,052 | 2,008 | 202,060 | 250,000 receipt |
| First publication, nonzero availability word (prior transaction) | 161,952 | 2,008 | 184,960 | 250,000 receipt |
| First publication with epoch gate | 184,573 | 2,020 | 207,593 | 250,000 receipt |
| Matching duplicate (full verification, no write) | 135,358 | 2,008 | 158,366 | none |

A nonzero first publication writes exactly the value mapping slot and one availability word;
a matching duplicate writes no slots and emits no event. The explicit storage-access tests
check this. The descriptor/key remain immutable code data. Rewards are excluded.

## Repaired implementation defect (audit round 2, finding 1)

The earlier version of these notes reported a medium-severity defect and referred to a proof in
`.imd-findings.json` and `test/scratch/DuplicateOffCurveProof.t.sol`; neither file was
delivered. The proof is now an ordinary test, `test/contracts/DuplicateOffCurveProof.t.sol`,
and the defect is fixed in `BeaconVerifier.submit`.

The defect: once a round was available, `submit` only parsed, compressed and hashed the supplied
affine signature and compared the hash with the stored value. Flipping bit 0 of byte 95 of the
round-1 fixture keeps x and the compression sign bit, so the compressed form, and its SHA-256,
are unchanged while the point is off the curve: `verify` rejected it with
`PrecompileFailure(0x0f)`, duplicate `submit` returned false. SPEC §4.3 requires rejection on
both paths. The fix runs the full `_verify` on the duplicate path and compares afterwards, so an
invalid duplicate reverts exactly as a first submission would; a matching valid duplicate still
returns false, writes nothing and emits nothing. `test_DuplicateRejectsInvalidPoint`, the fuzz
tests' duplicate checks and the invariant handler's y-flip mutation cover the class.

## Scope and specification differences

The assignment's test-only path restriction takes precedence over its broader Job 2 file
list; the accepted production implementation was left intact. SPEC §10.3 explicitly names
blst while the inherited suite provided noble alone: this test gap is closed with the new
blst cross-check. The accepted implementation's handwritten libraries are under `src/bls/`
rather than the `lib/` delivery path in the Job 2 description. This placement difference is
recorded here without relocating or claiming to externally audit those production files.
