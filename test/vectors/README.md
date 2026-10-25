# Test vectors

`bls12.json` is generated offline by `scripts/gen_bls12_vectors.mjs` and committed, because
the Foundry profile forbids `ffi` and network access. Its `provenance` object records the
generator and the libraries used.

- **Independent implementation:** `@noble/curves` 2.4.0 (`bls12-381`: RFC 9380 hash-to-curve,
  pairing, short-signature verification) with `@noble/hashes` 2. Nothing in the generator calls
  the Solidity code.
- **RFC 9380:** Appendix J.9.1 (`BLS12381G1_XMD:SHA-256_SSWU_RO_`, five messages with
  `u[0]`, `u[1]`, `Q0`, `Q1`, `P`) and K.1 (`expand_message_xmd` SHA-256, ten cases), parsed
  from the RFC text and cross-checked against noble before being written.
- **Signatures:** 109 valid group signatures (rounds 1–100, epoch boundaries 2880/2881 and
  5760/5761, round 120, 10⁶, 2³², `maxRound - 1` and `maxRound`), each with the 96-byte submit
  form, the 48-byte compressed form and `R = SHA256(compressed)`. Both compressed sign bits occur.
- **Threshold fixture:** 3-of-4 Shamir sharing of the group secret (share `i` at point `i + 1`),
  public shares, partial signatures and every 3-subset's Lagrange coefficients; all subsets
  reconstruct the same group signature.
- **Negative vectors:** infinity, a non-subgroup G1 point, an off-curve point, non-canonical
  coordinates, the negated signature, signatures under another key / another network id / a
  wrong epoch field, and group keys that are infinite, non-canonical, non-subgroup or in the
  wrong coefficient order.

**All keys are TEST-ONLY and NON-PRODUCTION.** They are SHA-256 of public labels so that
anyone can regenerate the fixture; they protect nothing and must never be used for a network.

To regenerate: install `@noble/curves@2.4.0` and `@noble/hashes@2` in a scratch directory,
download `rfc9380.txt` from the RFC Editor, then run
`NODE_PATH=<scratch>/node_modules node scripts/gen_bls12_vectors.mjs <path>/rfc9380.txt`.
