# BeaconVerifier gas report (Job 2)

Measured with the repository's own `foundry.toml` by `forge test --match-test testGas_ -vv`
(`make gas`). These are local Foundry (revm) measurements, not on-chain receipts; the
deployment job must re-measure on each target (SPEC §4.4, §10.3).

Revised after audit round 2 (finding 6): the gas tests now run isolated and report transaction
gas from the callee's frame, see "Method" below. The earlier report (forge 1.8.3) measured the
isolated transaction's gas with `gasleft()` around the call and then added intrinsic and calldata
gas a second time, so its "execution gas" and "receipt gas" were both overstated; the budgets were
met either way.

## Compiler profile

| Setting | Value |
|---|---|
| Foundry | forge 1.8.5 (`51a52c5`) |
| solc | 0.8.30, optimizer on, 200 runs, no `via_ir` |
| EVM | `prague` (EIP-2537 BLS12-381 precompiles 0x0b–0x11, EIP-2565 MODEXP, EIP-2929 access lists) |
| bytecode_hash | `none` |
| Gas schedule assumed | EIP-2537: PAIRING 37,700 + 32,600/pair, MAP_FP_TO_G1 5,500, G1ADD 375, G2MSM 22,500 (k = 1); MODEXP min 200 (Prague) / 500 (Osaka, EIP-7883) |

## Method

Every `testGas_` function carries `forge-config: default.isolate = true` and asserts
`vm.isIsolateMode()`. In isolated mode each external call made by the test is executed as its own
transaction, so warm storage can only come from a prior transaction, and
`vm.lastFrameGas().gasTotalUsed` of that call is the transaction's gas used: 21,000 intrinsic gas,
calldata gas (16 per non-zero byte, 4 per zero byte; 196 bytes for `submit(uint64,bytes)` with a
96-byte signature) and execution. The report lists that number as **receipt gas** and derives
**execution gas** as receipt − 21,000 − calldata. For `verify` (a `view` call, no transaction) the
frame's `gasTotalUsed` is the execution gas of the call itself, without the caller's CALL overhead.

Why isolation matters for the warm-word case: `testGas_SubmitFirstWriteWarmWord` makes the
availability word non-zero with round 16 and then measures round 17. Done inside one transaction,
the word is still warm and dirty when round 17 writes it (SLOAD 100 + SSTORE 100), which
undercounts the on-chain case by 4,800 gas; a relayer's transaction finds the word cold and
already non-zero (SLOAD 2,100 + SSTORE 2,900). The test now measures the same round 17 on a fresh
instance in the same run and asserts that the two receipts differ by exactly 17,100
(= 22,100 cold zero→non-zero − 5,000 cold non-zero→non-zero), which only holds when the warm
state comes from a prior transaction.

## Measurements

| Test | Case | Calldata gas | Execution gas | Receipt gas | Budget | Result |
|---|---|---|---|---|---|---|
| `testGas_VerifySingleRound` | `verify` round 17 (epoch 0) | n/a | 130,102 | n/a (view) | ≤ 170,000 execution | pass |
| `testGas_SubmitFirstWrite` | first write, epoch 0, availability word still zero | 2,008 | 179,052 | 202,060 | ≤ 250,000 receipt | pass |
| `testGas_SubmitFirstWriteWarmWord` | first write, epoch 0, availability word non-zero from a prior transaction | 2,008 | 161,952 | 184,960 | ≤ 250,000 receipt | pass |
| `testGas_SubmitFirstWriteWithEpochGate` | first write, epoch 1, `IEpochAuthority` consulted (mock) | 2,020 | 184,573 | 207,593 | ≤ 250,000 receipt | pass |
| `testGas_SubmitDuplicate` | matching duplicate of round 17 (returns false, no write, no event) | 2,008 | 135,358 | 158,366 | none (reported) | n/a |

Verification cost breakdown (nominal precompile schedule, two pairs, two maps): pairing
102,900 + maps 11,000 + G1ADD 375 + 2 × MODEXP 400 + 5 × SHA-256 ≈ 500 ≈ 115,200 of
arithmetic; the remainder (~15k) is Solidity memory handling, encoding checks and calls.

## Storage writes per first `submit`

| Slot | Write | Gas |
|---|---|---|
| `_values[round]` (mapping slot 0) | R(round), zero → non-zero | 22,100 (cold SSTORE) |
| `_available[round >> 8]` (mapping slot 1) | OR bit `round & 255` | 22,100 when the word is zero (every 256th round), otherwise 2,100 + 2,900 |
| event `RoundVerified` | 3 indexed topics, 32-byte value + 48-byte compressed signature | ≈ 2,800 |

The verifier has no other storage. The descriptor and group key are immutables (code), so
reading them costs no SLOAD.

## Duplicate submissions

Since audit round 2 (finding 1), a submission for an already available round runs the full
verification (encoding checks, hash-to-curve, pairing) and only then compares the result with the
stored value. Any invalid input therefore reverts with the same error a first submission gets; a
matching valid duplicate returns false and neither writes nor emits. The duplicate path costs
135,358 execution gas (158,366 receipt gas) instead of roughly 7,600 (30,600 receipt) when it only
re-hashed the compressed form. Duplicates have no budget; a relayer avoids the cost by reading
`get(round)` first. Rewards (Job 7) pay only on a `true` return, so the change does not affect
the fee accounting.

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
2,000 cases, set with inline `forge-config` comments; every case checks `verify`, a first
`submit` and a duplicate `submit` after the genuine signature was published. Both pass under the
pinned seed `0x21a72a54…c6ad` (`make test`), the previous seed `0x4c3111c9…de0a` and
arbitrary seeds.
