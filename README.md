# imd-beacon

A decentralized, unbiasable, publicly verifiable randomness beacon. It is signed by
[IMD](https://imd.fun) seats and built by the IMD agent swarm.

- Threshold BLS signatures, like drand, but with membership open to IMD seat holders
  instead of a fixed set of organizations
- Verifiable on EVM chains by a contract; anyone can relay a round
- Built piece by piece through IMD jobs; each piece lands here as a pull request

Status: **Job 2 delivered** (on-chain verifier). Start with [`docs/PLAN.md`](docs/PLAN.md)
and the contract, [`docs/SPEC.md`](docs/SPEC.md). Job 1 produced the spec; Job 2 produced
`src/BeaconVerifier.sol` (see [`ADAPTATION.md`](ADAPTATION.md) and
[`docs/verification-gas.md`](docs/verification-gas.md)).

Not for use with real value until it has had an external cryptography review.

## Building and testing (offline)

```sh
make build        # forge build with the repository's foundry.toml
make test         # whole suite, offline, verifier fuzz seed, 10,000-run fuzz tests included
make gas          # gas measurements behind docs/verification-gas.md
```

Dependencies are plain files in the tree: forge-std under `test/forge-std/`, the BLS
libraries under `src/bls/`, vectors under `test/vectors/`.

## BeaconVerifier

`src/BeaconVerifier.sol` verifies one round's BLS12-381 group signature with the EIP-2537
precompiles (signatures in G1, group key in G2, RFC 9380 hash-to-curve) and stores
`R(r) = SHA256(compressed signature)`. The ABI is `src/interfaces/IBeacon.sol`.

Constructor arguments (all fixed forever at deployment; there is no owner and no setter):

| Argument | Meaning |
|---|---|
| `networkId` | `keccak256("IMD_BEACON_NETWORK_V1" ‖ configHash)` from the frozen genesis descriptor |
| `genesisTime` | T0, release time of round 1 (seconds) |
| `key` | group key: eight 32-byte words of the 256-byte EIP-2537 affine G2 encoding |
| `epochAuthority` | contract answering `isEpochAuthorized(networkId, epoch)` for epochs ≥ 1 (registry on Ethereum, `EpochMirror` elsewhere; Job 3) |

Constants fixed in code, from SPEC v1: round period 30 s, epoch length 2,880 rounds, message
prefix `IMD_BEACON_ROUND_V1`, DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`. Gas caps
forwarded to precompiles (so a failing input cannot burn the caller's whole budget) are listed
in `docs/verification-gas.md`.

After launch: rounds of the genesis epoch can be submitted by anyone from `genesisTime`;
rounds of later epochs need the epoch authority to report them authorized. The relayer-fee
escrow (Job 7) wraps `submit` and pays only when it returns `true`.

License: MIT
