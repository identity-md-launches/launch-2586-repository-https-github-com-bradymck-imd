# Job 2 fixes: audit round 2 findings 1–6

Pull request description for the fix job (`jobs/02b-verifier-fixes.objective.txt`). Each finding
was handled in the order the brief requires: first a test that fails on the code as merged
(`main@0b93fd6`, verifier unchanged since `ff13e91`), then the change that makes it pass. Nothing
is deployed; `foundry.toml`, the ABI (`IBeacon`), the registry and rewards are untouched.

## Production change

`src/BeaconVerifier.sol`, `submit()`, duplicate path. Once a round is available the function now
runs the full `_verify` (length and canonical-coordinate checks, infinity check, hash-to-curve,
pairing) and only then compares the recomputed value with the stored one. A matching valid
duplicate still returns `false`, writes nothing and emits nothing; any invalid input reverts with
the error a first submission gets; a verified value that differs from the stored one reverts
`RoundValueMismatch` (unreachable with real SHA-256 because the BLS signature on (PK, M) is
unique, kept as a final check and covered through the SHA-256 mock). The epoch gate still applies
only to first writes, as before. The duplicate path now costs 135,358 execution gas (158,366
receipt gas) instead of about 7,600; duplicates have no budget. Relayers avoid it by reading
`get(round)` first.

## New and tightened tests, and the failure each showed before the fix

Run against the unfixed verifier with the verifier's fuzz seed
(`FOUNDRY_FUZZ_SEED=0x21a72a54…c6ad`): 7 failed, 48 passed. All seven failures are the
duplicate path.

### Finding 1: duplicate `submit` accepts invalid points

- `test_DuplicateRejectsInvalidPoint` (`test/contracts/BeaconVerifier.t.sol`): publishes round 1,
  then submits `offCurveG1Affine` and `nonSubgroupG1Affine` from `test/vectors/bls12.json` for
  round 1 expecting `PrecompileFailure(0x0f)` exactly, plus the y-flip of the round-1 signature
  (same x and sign bit, same compressed form); it also checks the same inputs get the same error
  for an unpublished round. Before the fix: `next call did not revert as expected`. The
  `offCurveG1Affine` fixture is the round-1 signature with y + 1, so it has the signature's x and
  sign bit and the old path returned `false` for it.
- `test/contracts/DuplicateOffCurveProof.t.sol`,
  `test_DuplicateSubmitRejectsOffCurvePointWithStoredPreimage`: the proof that
  `test/verification-notes.md` said was recorded in `.imd-findings.json` and
  `test/scratch/DuplicateOffCurveProof.t.sol` (neither existed), restored as an ordinary test:
  flip bit 0 of byte 95 of the round-1 fixture, show the compressed form and hash are unchanged,
  `verify` rejects, publish, duplicate `submit` must revert with `PrecompileFailure(0x0f)`.
  Before the fix: `off-curve duplicate with the stored preimage was accepted`. The stale
  references in the notes are replaced by this file.
- `test_NoDuplicateFee` tightened: the negated round-1 signature submitted as a duplicate must
  fail as `InvalidSignature` (a valid subgroup point failing the pairing), not as a value
  comparison. Before the fix: `RoundValueMismatch(1) != InvalidSignature()`.
- `test_DuplicateWithDifferentStoredValueReverts` (new): stores a zero value through the SHA-256
  mock that `test_ZeroRandomnessAvailability` is allowed to use, then resubmits the genuine
  signature without the mock and expects `RoundValueMismatch(42)`. This covers the comparison
  branch kept after the fix; it passes before and after (not a finding, coverage of the new code).

### Finding 2: `testFuzz_EncodingCannotChangeOutput`

Rewritten, still 10,000 runs. No unmodified runs. Each run picks one of the 109 independent
signatures and one of nine classes with its exact revert data: x + p and y + p
(`NonCanonicalFieldElement`), p − y (`InvalidSignature`), any non-empty subset of the flag bits
0x80/0x40/0x20 in the top byte of x (`NonCanonicalFieldElement`), infinity (`InfinityPoint`),
a y change keeping x and the sign bit (`PrecompileFailure(0x0f)`, asserted to keep the compressed
form), trailing bytes and truncation (`InvalidSignatureLength(len)`), and a single random byte
change (non-canonical when it lands at or above p, otherwise `PrecompileFailure(0x0f)`). Every
class is run against `verify`, a first `submit`, and a duplicate `submit` after the genuine
signature was published, with the stored value and the absence of events checked. Before the
fix, with the verifier seed: run 11, `RoundValueMismatch(62) != PrecompileFailure(0x0f)` on the
duplicate `submit` of a byte-flipped round-62 signature (`args=[61, 17, 34, 80, 209]`).

### Finding 3: `testFuzz_ModifiedSignatureFails`

Rewritten, 2,000 runs, no bare `expectRevert`, the no-op mask removed. Modes: a changed
coordinate (`PrecompileFailure(0x0f)`, or `NonCanonicalFieldElement` when the XOR lands at or
above p, decided by the same canonicality rule as the library), another round for the same
signature (`InvalidSignature`, including other epochs), swapped coordinates
(`PrecompileFailure(0x0f)`), the negated point, sig + G1 and 2·sig (G1ADD through the test
harness; valid subgroup points that must fail the pairing with `InvalidSignature`). Every mode
runs against `verify` and against `submit` after the mutated round's genuine signature has been
published. Before the fix: run 0, `RoundValueMismatch(37) != InvalidSignature()` for the negated
round-37 signature submitted as a duplicate (`args=[36, 6806, true, 3648550220149058142, 3]`).

### Finding 4: invariant handler malformed path

`rejectMalformedOrWrongSignature` in `test/contracts/BeaconVerifierInvariant.t.sol` now asserts
the exact revert data for the state: `RoundNotReleased(round, T(r))` before release,
`EpochNotAuthorized(epoch)` for an unpublished round of an unauthorized epoch, otherwise the
signature check's own error for the mutation (`InvalidSignatureLength(97)`, `InfinityPoint`,
`NonCanonicalFieldElement`, `PrecompileFailure(0x0f)` for the x change, and the new fifth
mutation, a y change keeping x and the sign bit, also `PrecompileFailure(0x0f)`). The
deterministic handler test exercises the new mutation in all three states. Before the fix:
`invariant_PublicationHistoryAndDescriptorRemainConsistent` failed with
`invalid input published or matched an existing round` (shrunk sequence: release, publish round
2881, reject with mutation seed 34 → y-flip, which the old duplicate path accepted), and
`test_HandlerExercisesFirstWritesDuplicatesEarlyAndEpochFailures` failed with
`invalid input reverted with unexpected data: RoundValueMismatch(1) != PrecompileFailure(0x0f)`
(x-flip of a published round).

### Finding 5: bare `vm.expectRevert()`

All seven replaced with exact data. `BeaconVerifier.t.sol`: the authority without code reverts
with empty data (the bool ABI decoder on empty return data), pinned as `expectRevert(bytes(""))`,
which Foundry matches only against an empty revert (checked: against `InvalidRound(0)` it fails
with `Error != expected error`); genesis with each missing precompile pins `InvalidGroupKey` for
G2MSM (0x0e) and `PrecompileFailure(addr)` for 0x02, 0x05, 0x0b, 0x0f, 0x10.
`BeaconVerifierAdversarial.t.sol`: the nine invalid first submissions each pin their own error
(`InfinityPoint`, `PrecompileFailure(0x0f)` ×2, `NonCanonicalFieldElement` ×2,
`InvalidSignature` ×4); the malformed authority returns (0, 1, 31 bytes, and the invalid bool
word) pin empty revert data; the reverting authority pins `Unavailable()`; the reverting
precompiles at genesis pin the same error as the wrong-length case. These are tightenings: the
code already reverted with these errors, so they pass before and after.

### Finding 6: `testGas_SubmitFirstWriteWarmWord`

All gas tests now carry `forge-config: default.isolate = true`, assert `vm.isIsolateMode()`, and
read `vm.lastFrameGas().gasTotalUsed`, the isolated transaction's gas (intrinsic + calldata +
execution). The warm-word test measures the same round 17 on a fresh instance in the same run
and asserts the two receipts differ by exactly 17,100 (cold zero→non-zero 22,100 minus cold
non-zero→non-zero 5,000), which only holds when the warm word comes from a prior transaction.
Measured against the old method (warm the word inside the test, `gasleft()` around the call), the
relation assertion fails without isolation with `21901 != 17100`: inside one transaction the word
is warm and dirty, so the undercount is 4,800 gas, not 2,100. With this Foundry's default
(isolated calls), the old method separated the transactions but reported the transaction's gas,
including 21,000 intrinsic and calldata gas, as "execution gas", and the report then added them
again as "receipt gas". `docs/verification-gas.md` is rewritten with the method and the corrected
numbers; the budgets hold with more margin than reported before:

| Case | Execution | Receipt | Budget |
|---|---:|---:|---:|
| verify round 17 | 130,102 | n/a | ≤ 170,000 execution |
| first submit, fresh word | 179,052 | 202,060 | ≤ 250,000 receipt |
| first submit, word non-zero from a prior transaction | 161,952 | 184,960 | ≤ 250,000 receipt |
| first submit, epoch gate | 184,573 | 207,593 | ≤ 250,000 receipt |
| matching duplicate (new `testGas_SubmitDuplicate`) | 135,358 | 158,366 | none |

## Checks run

- `forge build`, `forge fmt --check`: clean.
- `make test` (FOUNDRY_OFFLINE, verifier seed `0x21a72a54…c6ad`, now the Makefile default): 5
  suites, 55 tests passed, 0 failed, about 4 s. Also passing with the previous seed
  `0x4c3111c9…de0a` and seeds `0x1`, `0xdeadbeef`, `0x7777777777777777`.
- Not run: Slither (not available offline here), deployment smoke scripts (finding 7, moved to
  Job 9 by the review).

## Assumptions and operational notes

- The gas tests depend on Foundry's isolated execution (inline `isolate` config, forge ≥ 1.8).
- The 17,100 relation and the receipt numbers assume EIP-2929/EIP-3529 storage pricing and the
  Prague EIP-2537 schedule; a repriced target chain needs re-measurement (SPEC §4.4).
- No deployment parameters change: the constructor still needs the frozen genesis descriptor
  and the DKG group key (Jobs 3–4) before any launch.
