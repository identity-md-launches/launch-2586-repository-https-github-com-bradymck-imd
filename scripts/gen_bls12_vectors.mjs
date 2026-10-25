// SPDX-License-Identifier: MIT
// Generates test/vectors/bls12.json for the imd-beacon verifier (SPEC §4.3, §10.3 Job 2).
//
// Independent implementation: @noble/curves (bls12-381, RFC 9380 hash-to-curve, pairing),
// an audited TypeScript library. Nothing here calls the Solidity code, so the Solidity
// verifier is checked against an independent oracle plus the RFC 9380 appendix vectors.
//
// Usage (offline, run from the repository root):
//   npm install --prefix /tmp/noble @noble/curves@2.4.0 @noble/hashes@2
//   NODE_PATH=/tmp/noble/node_modules node scripts/gen_bls12_vectors.mjs path/to/rfc9380.txt
//
// ALL KEYS IN THE OUTPUT ARE TEST-ONLY AND NON-PRODUCTION. They are derived from public
// strings below so anyone can regenerate the fixture; they protect nothing.

import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { bls12_381: bls } = require('@noble/curves/bls12-381.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { keccak_256 } = require('@noble/hashes/sha3.js');

const Fp = bls.fields.Fp;
const Fp2 = bls.fields.Fp2;
const Fr = bls.fields.Fr;
const P = Fp.ORDER;
const R = Fr.ORDER;
const G1 = bls.G1.Point;
const G2 = bls.G2.Point;

const DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_';
const MSG_PREFIX = 'IMD_BEACON_ROUND_V1';
const PERIOD = 30n;
const EPOCH_LENGTH = 2880n;
const GENESIS_TIME = 1800000000n; // test descriptor only
const U64_MAX = (1n << 64n) - 1n;
const MAX_ROUND = (U64_MAX - GENESIS_TIME) / PERIOD + 1n;

const te = new TextEncoder();
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex');
const be = (n, len) => {
  const out = new Uint8Array(len);
  let v = BigInt(n);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  if (v !== 0n) throw new Error('overflow');
  return out;
};
const cat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const fp48 = (x) => be(x, 48);
const fp64 = (x) => be(x, 64);
const g1Affine96 = (pt) => { const a = pt.toAffine(); return cat(fp48(a.x), fp48(a.y)); };
const g1Eip128 = (pt) => { const a = pt.toAffine(); return cat(fp64(a.x), fp64(a.y)); };
const g2Eip256 = (pt) => {
  const a = pt.toAffine();
  return cat(fp64(a.x.c0), fp64(a.x.c1), fp64(a.y.c0), fp64(a.y.c1));
};
const g2Words = (pt) => {
  const b = g2Eip256(pt); const w = [];
  for (let i = 0; i < 8; i++) w.push(hex(b.slice(i * 32, i * 32 + 32)));
  return w;
};
const scalarFromLabel = (label) => {
  // Test-only key derivation from a public label: deterministic and obviously non-secret.
  const h = sha256(te.encode(label));
  return BigInt(hex(h)) % R || 1n;
};

// ---------------------------------------------------------------- RFC 9380 appendix vectors
function parseRfc(path) {
  const text = readFileSync(path, 'utf8').split('\n');
  const grab = (startMarker, endMarker) => {
    const s = text.findIndex((l) => l.startsWith(startMarker));
    const e = text.findIndex((l, i) => i > s && l.startsWith(endMarker));
    return text.slice(s, e);
  };
  // Joins continuation lines of "key = value" blocks into records.
  const records = (lines) => {
    const recs = []; let cur = null; let key = null;
    for (const raw of lines) {
      const l = raw.replace(/\r$/, '');
      if (/^\S/.test(l) || l.trim() === '') { continue; }
      const m = l.match(/^\s+(\S+)\s*=\s?(.*)$/);
      if (m) {
        key = m[1];
        if (key === 'msg') { cur = {}; recs.push(cur); }
        if (cur) cur[key] = m[2];
      } else if (cur && key) {
        cur[key] += l.trim();
      }
    }
    return recs;
  };
  const g1 = records(grab('J.9.1.  BLS12381G1_XMD:SHA-256_SSWU_RO_', 'J.9.2.'))
    .map((r) => ({
      msg: r.msg, dst: 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_',
      u0: '0x' + r['u[0]'], u1: '0x' + r['u[1]'],
      q0x: '0x' + r['Q0.x'], q0y: '0x' + r['Q0.y'], q1x: '0x' + r['Q1.x'], q1y: '0x' + r['Q1.y'],
      px: '0x' + r['P.x'], py: '0x' + r['P.y'],
    }));
  const xmd = records(grab('K.1.  expand_message_xmd(SHA-256)', 'K.2.'))
    .filter((r) => r.uniform_bytes)
    .map((r) => ({
      msg: r.msg, dst: 'QUUX-V01-CS02-with-expander-SHA256-128',
      lenInBytes: Number(r.len_in_bytes), uniformBytes: '0x' + r.uniform_bytes,
    }));
  if (g1.length !== 5 || xmd.length !== 10) throw new Error(`rfc parse: g1=${g1.length} xmd=${xmd.length}`);
  // Cross-check the RFC vectors against noble before emitting them.
  for (const v of g1) {
    const pt = bls.G1.hashToCurve(te.encode(v.msg), { DST: v.dst }).toAffine();
    if (pt.x !== BigInt(v.px) || pt.y !== BigInt(v.py)) throw new Error('noble disagrees with RFC 9380 J.9.1');
  }
  return { expandMessageXmd: xmd, hashToCurveG1: g1 };
}

// ---------------------------------------------------------------- network + key fixture
const configHash = keccak_256(te.encode('IMD_BEACON_TEST_CONFIG_NONPRODUCTION'));
const networkId = keccak_256(cat(te.encode('IMD_BEACON_NETWORK_V1'), configHash));
const otherNetworkId = keccak_256(cat(te.encode('IMD_BEACON_NETWORK_V1'), keccak_256(te.encode('OTHER_TEST_CONFIG'))));

const epochOf = (r) => (r - 1n) / EPOCH_LENGTH;
const roundTime = (r) => GENESIS_TIME + PERIOD * (r - 1n);
const messageFor = (nid, epoch, round) => cat(te.encode(MSG_PREFIX), nid, be(epoch, 8), be(round, 8));

const sk = scalarFromLabel('IMD_BEACON_TEST_ONLY_GROUP_KEY_V1 non-production do not use');
const pk = G2.BASE.multiply(sk);
const skOther = scalarFromLabel('IMD_BEACON_TEST_ONLY_OTHER_KEY_V1 non-production do not use');
const pkOther = G2.BASE.multiply(skOther);

const signMsg = (secret, msg) => bls.G1.hashToCurve(msg, { DST }).multiply(secret);
const roundRecord = (secret, nid, r, epochOverride) => {
  const epoch = epochOverride ?? epochOf(r);
  const msg = messageFor(nid, epoch, r);
  const sig = signMsg(secret, msg);
  const compressed = sig.toBytes(true);
  if (compressed.length !== 48) throw new Error('compressed length');
  // Verify with noble's own short-signature verifier (independent of our arithmetic above).
  if (!bls.shortSignatures.verify(sig, bls.G1.hashToCurve(msg, { DST }), G2.BASE.multiply(secret))) throw new Error('noble verify failed');
  return {
    round: r.toString(), epoch: epoch.toString(), roundTime: roundTime(r).toString(),
    message: hex(msg),
    signatureAffine: hex(g1Affine96(sig)),
    signatureCompressed: hex(compressed),
    value: hex(sha256(compressed)),
  };
};

const roundList = [];
for (let r = 1n; r <= 100n; r++) roundList.push(r);
for (const r of [2880n, 2881n, 5760n, 5761n, 120n, 1000000n, 4294967296n, MAX_ROUND - 1n, MAX_ROUND]) roundList.push(r);
const rounds = roundList.map((r) => roundRecord(sk, networkId, r));
const signBits = rounds.map((v) => (parseInt(v.signatureCompressed.slice(2, 4), 16) & 0x20) !== 0);
if (!signBits.includes(true) || !signBits.includes(false)) throw new Error('fixture must cover both sign bits');

// ---------------------------------------------------------------- threshold fixture (4-of-3)
const N = 4, T = 3;
const coeffs = [sk];
for (let i = 1; i < T; i++) coeffs.push(scalarFromLabel(`IMD_BEACON_TEST_ONLY_POLY_COEFF_${i} non-production`));
const evalPoly = (x) => { let acc = 0n; for (let i = coeffs.length - 1; i >= 0; i--) acc = (acc * x + coeffs[i]) % R; return acc; };
const shares = [];
for (let i = 0; i < N; i++) shares.push(evalPoly(BigInt(i + 1)));
const thRound = 7n;
const thMsg = messageFor(networkId, epochOf(thRound), thRound);
const H = bls.G1.hashToCurve(thMsg, { DST });
const partials = shares.map((s) => H.multiply(s));
const groupSig = H.multiply(sk);
const modInv = (a) => Fr.inv(((a % R) + R) % R);
const lagrange = (S, i) => {
  let num = 1n, den = 1n;
  for (const j of S) { if (j === i) continue; num = (num * BigInt(j + 1)) % R; den = (den * ((BigInt(j + 1) - BigInt(i + 1) + R) % R)) % R; }
  return (num * modInv(den)) % R;
};
const subsets = [];
for (let a = 0; a < N; a++) for (let b = a + 1; b < N; b++) for (let c = b + 1; c < N; c++) subsets.push([a, b, c]);
const subsetRecords = subsets.map((S) => {
  let acc = G1.ZERO;
  for (const i of S) acc = acc.add(partials[i].multiply(lagrange(S, i)));
  if (!acc.equals(groupSig)) throw new Error('threshold reconstruction mismatch');
  return { indices: S, lambdas: S.map((i) => '0x' + lagrange(S, i).toString(16)) };
});
const threshold = {
  note: 'TEST-ONLY shares, non-production. Shamir polynomial degree t-1 over Fr, share i at point i+1 (SPEC §4.3).',
  n: N, t: T, round: thRound.toString(), message: hex(thMsg),
  hashToCurveAffine: hex(g1Affine96(H)),
  shares: shares.map((s, i) => ({ index: i, secretShare: '0x' + s.toString(16), publicShareEip256: hex(g2Eip256(G2.BASE.multiply(s))), partialAffine: hex(g1Affine96(partials[i])) })),
  subsets: subsetRecords,
  groupSignatureAffine: hex(g1Affine96(groupSig)),
  groupSignatureCompressed: hex(groupSig.toBytes(true)),
  value: hex(sha256(groupSig.toBytes(true))),
};

// ---------------------------------------------------------------- negative vectors
function findNonSubgroupG1() {
  for (let i = 1n; ; i++) {
    const x = (BigInt(hex(sha256(te.encode(`nonsubgroup-g1-${i}`)))) % P);
    const rhs = Fp.add(Fp.pow(x, 3n), 4n);
    let y; try { y = Fp.sqrt(rhs); } catch { continue; }
    const pt = G1.fromAffine({ x, y });
    if (!pt.isTorsionFree()) {
      if (Fp.sqr(y) !== rhs) throw new Error('sqrt');
      return pt;
    }
  }
}
function findNonSubgroupG2() {
  for (let i = 1n; ; i++) {
    const c0 = BigInt(hex(sha256(te.encode(`nonsubgroup-g2-${i}-c0`)))) % P;
    const c1 = BigInt(hex(sha256(te.encode(`nonsubgroup-g2-${i}-c1`)))) % P;
    const x = { c0, c1 };
    const rhs = Fp2.add(Fp2.pow(x, 3n), Fp2.mul(Fp2.create({ c0: 4n, c1: 4n }), Fp2.ONE));
    let y; try { y = Fp2.sqrt(rhs); } catch { continue; }
    if (!Fp2.eql(Fp2.sqr(y), rhs)) continue;
    const pt = G2.fromAffine({ x, y });
    if (!pt.isTorsionFree()) return pt;
  }
}
const nsG1 = findNonSubgroupG1();
const nsG2 = findNonSubgroupG2();
const sig1 = rounds[0];
const sig1x = BigInt('0x' + sig1.signatureAffine.slice(2, 98));
const sig1y = BigInt('0x' + sig1.signatureAffine.slice(98));
const pkA = pk.toAffine();
const negative = {
  infinityAffine: hex(new Uint8Array(96)),
  nonSubgroupG1Affine: hex(g1Affine96(nsG1)),
  offCurveG1Affine: hex(cat(fp48(sig1x), fp48((sig1y + 1n) % P))),
  nonCanonicalXAffine: hex(cat(fp48(sig1x + P), fp48(sig1y))),
  nonCanonicalYAffine: hex(cat(fp48(sig1x), fp48(sig1y + P))),
  negatedSignatureAffine: hex(cat(fp48(sig1x), fp48(P - sig1y))),
  wrongKeyRound1: roundRecord(skOther, networkId, 1n),
  otherNetworkRound1: roundRecord(sk, otherNetworkId, 1n),
  wrongEpochRound1: roundRecord(sk, networkId, 1n, 1n),
  groupKeyWrongCoefficientOrderWords: (() => {
    const b = cat(fp64(pkA.x.c1), fp64(pkA.x.c0), fp64(pkA.y.c1), fp64(pkA.y.c0)); const w = [];
    for (let i = 0; i < 8; i++) w.push(hex(b.slice(i * 32, i * 32 + 32))); return w;
  })(),
  groupKeyNonSubgroupWords: g2Words(nsG2),
  groupKeyInfinityWords: Array(8).fill(hex(new Uint8Array(32))),
  groupKeyNonCanonicalWords: (() => {
    const b = cat(fp64(pkA.x.c0 + P), fp64(pkA.x.c1), fp64(pkA.y.c0), fp64(pkA.y.c1)); const w = [];
    for (let i = 0; i < 8; i++) w.push(hex(b.slice(i * 32, i * 32 + 32))); return w;
  })(),
  otherGroupKeyWords: g2Words(pkOther),
};

// ---------------------------------------------------------------- constants
const g2neg = G2.BASE.negate();
const constants = {
  p: '0x' + P.toString(16),
  r: '0x' + R.toString(16),
  g1GeneratorEip128: hex(g1Eip128(G1.BASE)),
  g2GeneratorEip256: hex(g2Eip256(G2.BASE)),
  g2GeneratorNegatedEip256: hex(g2Eip256(g2neg)),
  g2GeneratorNegatedWords: g2Words(g2neg),
};

const out = {
  provenance: {
    generator: 'scripts/gen_bls12_vectors.mjs',
    independentImplementation: '@noble/curves 2.4.0 (bls12-381, RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_, pairing) with @noble/hashes 2',
    rfc: 'RFC 9380 Appendix J.9.1 (hash-to-curve) and K.1 (expand_message_xmd SHA-256), parsed from rfc9380.txt',
    keys: 'TEST-ONLY, NON-PRODUCTION. Scalars are SHA-256 of public labels; nothing is secret.',
    spec: 'docs/SPEC.md §4.3: M = "IMD_BEACON_ROUND_V1" || networkId || U64BE(E(r)) || U64BE(r); R = SHA256(compressed G1 signature)',
  },
  constants,
  rfc9380: parseRfc(process.argv[2] ?? '/tmp/dl/rfc9380.txt'),
  network: {
    networkId: hex(networkId), otherNetworkId: hex(otherNetworkId),
    genesisTime: GENESIS_TIME.toString(), period: Number(PERIOD), epochLength: Number(EPOCH_LENGTH),
    maxRound: MAX_ROUND.toString(), dst: DST, messagePrefix: MSG_PREFIX,
  },
  key: {
    note: 'TEST-ONLY group key, non-production',
    secretKey: '0x' + sk.toString(16),
    groupKeyCompressed: hex(pk.toBytes(true)),
    groupKeyEip256: hex(g2Eip256(pk)),
    groupKeyWords: g2Words(pk),
    otherSecretKey: '0x' + skOther.toString(16),
  },
  rounds,
  threshold,
  negative,
};
writeFileSync('test/vectors/bls12.json', JSON.stringify(out, null, 1) + '\n');
console.log(`wrote test/vectors/bls12.json: ${rounds.length} rounds, ${subsetRecords.length} subsets, maxRound=${MAX_ROUND}`);
