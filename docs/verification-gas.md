# BeaconVerifier gas report (Job 2)

Measured with the repository's own `foundry.toml` by `forge test --match-test testGas_ -vv`
(`make gas`). These are local Foundry (revm) measurements, not on-chain receipts; the
deployment job must re-measure on each target (SPEC §4.4, §10.3).

## Compiler profile

| Setting | Value |
|---|---|
| Foundry | forge 1.8.3 (`cae51ad`) |
| solc | 0.8.30, optimizer on, 200 runs, no `via_ir` |
| EVM | `prague` (EIP-2537 BLS12-381 precompiles 0x0b–0x11, EIP-2565 MODEXP) |
| bytecode_hash | `none` |
| Gas schedule assumed | EIP-2537: PAIRING 37,700 + 32,600/pair, MAP_FP_TO_G1 5,500, G1ADD 375, G2MSM 22,500 (k = 1); MODEXP min 200 (Prague) / 500 (Osaka, EIP-7883) |

## Measurements

Execution gas is measured as `gasleft()` around the external call from the test contract,
after warming the verifier address (a transaction's `to` is warm). It therefore includes the
CALL overhead and return-data copying, so the on-chain execution gas is slightly lower.
Receipt gas = 21,000 intrinsic + calldata gas (16 per non-zero byte, 4 per zero byte, 196
bytes for `submit(uint64,bytes)` with a 96-byte signature) + execution.

| Test | Case | Execution gas | Receipt gas | Budget | Result |
|---|---|---|---|---|---|
| `testGas_VerifySingleRound` | `verify` round 17 (epoch 0) | 135,374 | n/a (view) | ≤ 170,000 execution | pass |
| `testGas_SubmitFirstWrite` | first write, epoch 0, availability word still zero | 207,393 | 230,401 | ≤ 250,000 receipt | pass |
| `testGas_SubmitFirstWriteWarmWord` | first write, epoch 0, availability word already non-zero | 190,294 | 213,302 | ≤ 250,000 receipt | pass |
| `testGas_SubmitFirstWriteWithEpochGate` | first write, epoch 1, `IEpochAuthority` consulted (mock) | 212,926 | 235,946 | ≤ 250,000 receipt | pass |

Calldata gas for the measured rounds: 2,008–2,020.

Verification cost breakdown (nominal precompile schedule, two pairs, two maps): pairing
102,900 + maps 11,000 + G1ADD 375 + 2 × MODEXP 400 + 5 × SHA-256 ≈ 500 ≈ 115,200 of
arithmetic, the remainder (~20k) is Solidity memory handling, encoding checks and calls.

## Storage writes per first `submit`

| Slot | Write | Gas |
|---|---|---|
| `_values[round]` (mapping slot 0) | R(round), zero → non-zero | 22,100 (cold SSTORE) |
| `_available[round >> 8]` (mapping slot 1) | OR bit `round & 255` | 22,100 when the word is zero (every 256th round), otherwise 2,100 + 2,900 |
| event `RoundVerified` | 3 indexed topics, 32-byte value + 48-byte compressed signature | ≈ 2,800 |

The verifier has no other storage. The descriptor and group key are immutables (code), so
reading them costs no SLOAD. Duplicate submissions of an available round do not write and
do not run the pairing: they parse the encoding, recompute SHA256 of the compressed form and
compare it with the stored value (unique signatures make this equivalent to full
verification), costing well under 10,000 gas.

Deployment (one-time) additionally runs the genesis self-test: G2MSM over the group key,
a hash-to-curve known answer and one pairing identity check (≈ 150,000 gas in total).

## Bounded gas on failed precompile calls

Every precompile call forwards a fixed cap (`BLS12381.sol`: SHA-256 5,000, MODEXP 10,000,
G1ADD 3,000, MAP_FP_TO_G1 20,000, PAIRING 250,000, G2MSM 60,000), several times the nominal
cost. A failing precompile consumes all gas it is given, so without the cap an invalid
submission (for example a non-subgroup point) burned the caller's entire gas budget. If a
target chain reprices a precompile above a cap, verification fails closed there; revise the
caps and this report before deploying to such a chain (SPEC §4.4).

## Fuzz runs

`testFuzz_EncodingCannotChangeOutput` runs 10,000 cases and `testFuzz_ModifiedSignatureFails`
2,000 cases, set with inline `forge-config` comments; both pass under the pinned seed
`0x4c3111c9…de0a` (`make test`).
