# Review of Job 2 (verifier contract)

The verifier was built by IMD launch job
[`044913fb-4465-4c2c-bfda-2d75d43a9659`](https://explorer.imd.fun/jobs/044913fb-4465-4c2c-bfda-2d75d43a9659),
which targeted Sepolia. Code, tests and five audit nodes (economics, flow, imported code, math,
permissions) were accepted. The launch then **blocked at the deploy manifest**, correctly: the
constructor needs a genesis descriptor and a DKG group key that don't exist yet (Jobs 3–4), and
the verifier is immutable. Nothing was deployed.

The code was taken from the accepted submissions' git bundles:
`adapt_contract_project` (sha256 `fd65171a…`) and `write_foundry_tests` (sha256 `5ae8deff…`),
both matching the hashes IMD published. They apply on top of `main@71252e8`.

## Checked

- `foundry.toml` is unchanged. The only `docs/SPEC.md` edit is a consistency fix in §4.4:
  "250k execution budget" becomes "250k receipt budget", matching R6 and §10.3.
- `src/BeaconVerifier.sol` has no owner, admin, setter, `delegatecall`, payable or token logic.
  The descriptor and group key are immutables. The constructor runs a genesis self-test.
  `M(r)` matches SPEC §4.3. `submit` checks release time, uses an explicit availability bitmap,
  makes a matching duplicate a no-op returning `false` and reverts on a mismatch. The
  `IEpochAuthority` call is `view` (STATICCALL), consulted only for epochs ≥ 1.
- The reported gas is within budget: `verify` 135,374 (≤ 170,000), first `submit` receipt
  230,401 (≤ 250,000). 10,000-run encoding fuzz.
- `test/vectors/vendor/pyblst/…/pyblst.cpython-312-x86_64-linux-gnu.so` is byte-identical to the
  `.so` in the official PyPI wheel `pyblst-0.3.15-cp312-…manylinux…x86_64` (wheel sha256
  `6d9143ed…`, `.so` sha256 `ad947928…`). It is only used by the offline vector generator, not
  by the Solidity tests.

## Not yet done

- ~~Run the test suite locally.~~ **Done 2026-10-25:** `make test` (forge 1.8.5) ran 4 suites,
  **51 tests passed, 0 failed, 0 skipped**. That agrees with IMD's verifier ("all checks passed").
- Line-by-line review of `src/bls/BLS12381.sol` and `src/bls/HashToCurveG1.sol` (encoding
  checks, subgroup handling, gas caps) is still owed. It belongs in the Job 8 external audit
  regardless.

## Audit round 2 (2026-10-26): blocking findings

The crypto core was reviewed line by line. The `p`, `(p-1)/2`, G1 generator and negated-G2
constants were re-derived. The RFC 9380 vectors in `test/vectors/bls12.json` all match the
RFC text (50 of 50 hex values). An adversarial review of the test suite found the following.
**Do not merge until 1–4 are fixed with tests that fail on the current code first.**

1. **Medium, verifier bug: a duplicate `submit` accepts invalid points.** `src/BeaconVerifier.sol`
   lines 130–136: once a round is available, the duplicate path only parses, compresses and
   hashes. It never runs the pairing, so an off-curve or non-subgroup point with the same x and
   sign bit returns `false` instead of reverting. That breaks SPEC "invalid submissions revert".
   The swarm's own notes (`test/verification-notes.md` lines 68–82) record this finding, but
   the referenced `.imd-findings.json` and `test/scratch/DuplicateOffCurveProof.t.sol` were not
   delivered, and the invariant handler deliberately avoids the case. Fix: run the full
   `_verify` on duplicates, then compare with the stored value.
2. **Medium, test:** `testFuzz_EncodingCannotChangeOutput` (`BeaconVerifier.t.sol:482–507`).
   25% of runs are unmodified, one mode uses a bare `expectRevert`, and random flips almost
   never produce x+p, y+p, p−y or flag-bit encodings. Target those classes with exact
   selectors, against `verify`, a first `submit` and a duplicate `submit`.
3. **Medium, test:** `testFuzz_ModifiedSignatureFails` only tests `verify`. Modes 0 and 2 use
   bare reverts, and the `:529` mask is a no-op. Pin `PrecompileFailure(0x0f)`, add sig+G1 and
   2·sig, and run every mode against `submit` after the round is published. That would have
   caught #1.
4. **Medium, test:** the invariant handler's malformed path (`BeaconVerifierInvariant.t.sol:142–143`)
   accepts any revert. Assert the expected revert data per state, and add a y-flip mutation.
5. **Low:** bare `expectRevert` at `BeaconVerifier.t.sol:355,403` and
   `BeaconVerifierAdversarial.t.sol:119,168,174,190,400`. Pin the selectors.
6. **Low:** `testGas_SubmitFirstWriteWarmWord` warms the word slot in the same transaction, so
   it undercounts by about 2,100 gas.
7. **Gap:** the SPEC §10.3 deployment smoke scripts (positive, negative, malformed and subgroup
   vectors on all 7 precompiles) do not exist yet. They can move to Job 9.

## Notes for later jobs

- **Job 7 (rewards):** the escrow must pay only when `submit` returns `true`. Note that the
  duplicate path is currently wrong (audit round 2, finding 1). An earlier version of this
  review called it "safe because nothing is paid"; that underrated the spec violation.
- **Job 3** must implement `IEpochAuthority` for the registry and each `EpochMirror`.
- **Job 9:** a real launch needs the frozen genesis descriptor and the DKG group key. Don't
  open a contracts *launch* again until those exist.
