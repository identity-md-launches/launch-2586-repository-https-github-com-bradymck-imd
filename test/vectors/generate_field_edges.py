#!/usr/bin/env python3
"""NON-PRODUCTION field-reduction oracle using only Python's standard library.

Run offline from the repository root: python3 test/vectors/generate_field_edges.py
The BLS12-381 base-field modulus is from RFC 9380 section 8.8.1. Python arbitrary
precision integer remainder, independent of Solidity and MODEXP, is the oracle.
No secrets, signing keys, network access, external packages, or FFI are used.
"""
import json
from pathlib import Path

P = int("1a0111ea397fe69a4b1ba7b6434bacd7"
        "64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
INPUTS = [0, 1, P - 1, P, P + 1, 2 * P - 1, 2 * P, 2 * P + 1,
          2**384 - 1, 2**511, 2**512 - 1, int.from_bytes(bytes(range(64)), "big")]
CASES = [{"wide": "0x" + n.to_bytes(64, "big").hex(),
          "paddedResult": "0x" + (n % P).to_bytes(64, "big").hex()}
         for n in INPUTS]
OUTPUT = {"provenance": "Python 3 arbitrary precision integer %; generate_field_edges.py; RFC 9380 8.8.1 modulus",
          "count": len(CASES), "cases": CASES}
Path("test/vectors/field-edges.json").write_text(json.dumps(OUTPUT, indent=2) + "\n")
