#!/usr/bin/env python3
"""Offline, NON-PRODUCTION blst oracle; no Solidity, RPC, FFI or downloaded dependencies.

Run: python3 -B test/vectors/generate_blst_crosscheck.py
The committed pyblst wheel targets CPython 3.12 / Linux x86_64. Forge reads the JSON
only and has no Python, native-module or platform dependency.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "vendor/pyblst"))
from pyblst import BlstP1Element as P1, BlstP2Element as P2, final_verify, miller_loop

P = int("1a0111ea397fe69a4b1ba7b6434bacd7"
        "64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
# Standard compressed G2 generator, x.c1 || x.c0, as in BLS serialization.
G2 = P2.uncompress(bytes.fromhex(
    "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"))


def raw(value):
    return bytes.fromhex(value.removeprefix("0x"))


def hx(value):
    return "0x" + value.hex()


def affine(point):
    """Decode blst's compressed point with Python integer sqrt, not Solidity code."""
    encoded = point.compress()
    assert encoded[0] & 0x80 and not encoded[0] & 0x40
    x = int.from_bytes(encoded, "big") & ((1 << 381) - 1)
    assert x < P
    rhs = (x**3 + 4) % P
    y = pow(rhs, (P + 1) // 4, P)
    assert y * y % P == rhs
    if bool(encoded[0] & 0x20) != (y > P // 2):
        y = P - y
    return x.to_bytes(48, "big") + y.to_bytes(48, "big")


fixture_bytes = (HERE / "bls12.json").read_bytes()
fixture = json.loads(fixture_bytes)
network = fixture["network"]
sk = int(fixture["key"]["secretKey"], 16)  # PUBLIC, TEST-ONLY, NON-PRODUCTION
pk = G2.scalar_mul(sk)
assert pk.compress() == raw(fixture["key"]["groupKeyCompressed"])
dst = network["dst"].encode("ascii")


def hash_point(message, domain=dst):
    # Despite the wrapper's local variable names, its positional arguments are
    # (message, DST): src/lib.rs calls blst_hash_to_g1(out, arg1, len1, arg2, len2,...).
    return P1.hash_to_group(message, domain)


def round_case(round_number):
    epoch = (round_number - 1) // 2880
    message = (b"IMD_BEACON_ROUND_V1" + raw(network["networkId"])
               + epoch.to_bytes(8, "big") + round_number.to_bytes(8, "big"))
    assert len(message) == 67
    h = hash_point(message)
    signature = h.scalar_mul(sk)
    assert final_verify(miller_loop(signature, G2), miller_loop(h, pk))
    compressed = signature.compress()
    # Also exercise blst's canonical decoder and subgroup checks.
    assert P1.uncompress(compressed) == signature
    return {"round": str(round_number), "epoch": str(epoch),
            "roundTime": str(int(network["genesisTime"]) + 30 * (round_number - 1)),
            "message": hx(message), "hashToCurveAffine": hx(affine(h)),
            "signatureAffine": hx(affine(signature)),
            "signatureCompressed": hx(compressed), "value": hx(hashlib.sha256(compressed).digest())}


rounds = []
for original in fixture["rounds"]:
    case = round_case(int(original["round"]))
    for field in original:
        assert case[field] == original[field], (original["round"], field)
    rounds.append(case)

boundaries = [255, 256, 257, 511, 512, 513]
rounds.extend(round_case(round_number) for round_number in boundaries)

rfc = []
for case in fixture["rfc9380"]["hashToCurveG1"]:
    point = hash_point(case["msg"].encode("ascii"), case["dst"].encode("ascii"))
    encoded = affine(point)
    assert encoded == raw(case["px"]) + raw(case["py"])
    rfc.append({"message": hx(case["msg"].encode("ascii")), "dst": case["dst"], "pointAffine": hx(encoded)})

th = fixture["threshold"]
h = hash_point(raw(th["message"]))
assert hx(affine(h)) == th["hashToCurveAffine"]
partials = []
for share in th["shares"]:
    partial = h.scalar_mul(int(share["secretShare"], 16))
    assert hx(affine(partial)) == share["partialAffine"]
    partials.append(partial)
expected = h.scalar_mul(sk)
assert hx(affine(expected)) == th["groupSignatureAffine"]
for subset in th["subsets"]:
    total = P1()
    for index, scalar in zip(subset["indices"], subset["lambdas"]):
        total = total + partials[index].scalar_mul(int(scalar, 0))
    assert total == expected

vendor = HERE / "vendor/pyblst"
wheel = json.loads((vendor / "pyblst-download.json").read_text())
output = {
    "provenance": {
        "generator": "test/vectors/generate_blst_crosscheck.py",
        "library": "blst 0.3.16 through pyblst 0.3.15 (upstream wheel and Rust Cargo.lock committed)",
        "blstRevision": "e7f90de551e8df682f3cc99067d204d8b90d27ad",
        "blstSource": "https://github.com/supranational/blst/tree/e7f90de551e8df682f3cc99067d204d8b90d27ad",
        "wheelSha256": wheel["digests"]["sha256"],
        "wheelUrl": wheel["url"],
        "nobleFixtureSha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "keys": "PUBLIC TEST-ONLY NON-PRODUCTION scalar already present in bls12.json; no new secret material",
        "verification": "all 109 noble signatures/messages/encodings/outputs match blst; all pairings verified with blst; RFC J.9.1 checked; all 3-of-4 threshold subsets checked",
        "affineEncoding": "blst compressed G1 -> Python integer square root over RFC base field -> canonical x||y; output SHA256 uses hashlib"
    },
    "originalCount": len(fixture["rounds"]), "count": len(rounds),
    "boundaryRounds": boundaries, "rounds": rounds, "rfc9380": rfc,
    "threshold": {"round": th["round"], "subsetCount": len(th["subsets"]),
                  "groupSignatureAffine": hx(affine(expected)), "groupSignatureCompressed": hx(expected.compress())}
}
(HERE / "blst-crosscheck.json").write_text(json.dumps(output, indent=2) + "\n")
print(f"blst: {len(rounds)} signatures/pairings; {len(rfc)} RFC points; {len(th['subsets'])} threshold subsets; all match")
