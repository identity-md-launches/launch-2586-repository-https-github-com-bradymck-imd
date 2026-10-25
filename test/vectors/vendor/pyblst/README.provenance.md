# Test-only blst oracle dependency

This directory vendors the ordinary extracted files of the official PyPI wheel
`pyblst-0.3.15-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`.
It is used only to regenerate committed test vectors, never by Solidity or `forge test`.
The wheel is 340,715 bytes; its SHA-256 is
`6d9143edc459af7bcc43a1ff73cfcf3227a6f848a4140fde2cb41531ca34db95`.
The exact URL and digest are in `pyblst-download.json`. Wheel `RECORD` retains the upstream
per-file hashes. The native extension is kept so regeneration works offline without a compiler,
pip, a package registry, or Rust dependencies. Generation targets CPython 3.12 / Linux x86_64.

`source/` retains the upstream Rust binding, Cargo manifests/lockfile, packaging manifest,
README and MIT licence from the official source distribution. Its URL and SHA-256 are in
`pyblst-source-provenance.json`. These files are unmodified. The upstream wheel/source release
is named 0.3.15; the upstream Cargo package field still reads 0.3.14. Its dependency and lockfile
pin **blst 0.3.16**, crate checksum
`dcdb4c7013139a150f9fc55d123186dbfaba0d912817466282c73ac49e71fb45`.

The blst upstream release is [v0.3.16 at e7f90de551e8df682f3cc99067d204d8b90d27ad](https://github.com/supranational/blst/tree/e7f90de551e8df682f3cc99067d204d8b90d27ad).
`BLST-LICENSE` is its Apache-2.0 licence. The Python/Rust wrapper is MIT licensed; its notice
is preserved in `source/LICENSE.txt` and the upstream wheel's `licenses/LICENSE.txt`.
No git repository or submodule is part of this vendored directory.

The generator uses these binding operations: `BlstP1Element.hash_to_group`, `scalar_mul`,
`compress`, `uncompress`, addition/equality, `BlstP2Element.uncompress`/`scalar_mul`,
`miller_loop`, and `final_verify`. The binding source was read to verify the argument order,
scalar conversion, subgroup checks during decompression, and pairing argument conversion.
Its `hash_to_group` local variable names are misleading: the actual C call takes the first
argument as the message and the second as DST. The generator uses that C call order and
checks the result against RFC points and all existing noble signatures before writing output.

Affine G1 output is decoded from blst's compressed output with Python integer arithmetic over
the RFC field, including the standard compression sign choice. Output hashes use Python
`hashlib.sha256`. The scalar is the already-public, explicitly NON-PRODUCTION test scalar in
`bls12.json`; no new secret material is generated. This fixture work makes no claim about
production key handling or an external audit of the project's Solidity implementation.
