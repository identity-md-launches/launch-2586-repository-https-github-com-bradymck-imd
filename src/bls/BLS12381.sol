// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title BLS12381: encodings and EIP-2537 precompile wrappers for the imd-beacon verifier
/// @notice Written for imd-beacon (SPEC §4.3) and reviewed line by line for this repository.
///         It is not adapted from randa-mu/bls-solidity; see ADAPTATION.md.
///
///         Conventions
///         - A base-field element Fp is handled as two 256-bit words `(hi, lo)` in the
///           EIP-2537 64-byte padded layout: `hi` is bytes 0..32 (sixteen zero bytes followed by
///           the top sixteen bytes of the 48-byte big-endian integer), `lo` is bytes 32..64.
///         - A G1 point in "EIP form" is 128 bytes `pad64(x) || pad64(y)`; a G2 point is 256 bytes
///           `pad64(x.c0) || pad64(x.c1) || pad64(y.c0) || pad64(y.c1)` (EIP coefficient order).
///         - The submit form of a G1 signature is 96 bytes `x || y`, each a canonical 48-byte
///           big-endian integer strictly below p, with no flag bits (SPEC §4.3).
///         - The compressed form is the standard 48-byte ZCash/IETF encoding: x with the top byte
///           OR-ed with 0x80 (compressed) and 0x20 when y is the lexicographically larger root.
///
///         Every precompile call must succeed and return exactly the expected number of bytes;
///         a successful call to an empty account (missing precompile) returns no data and is
///         treated as failure (SPEC §4.3, R6).
library BLS12381 {
    // ---------------------------------------------------------------- errors
    error PrecompileFailure(address precompile);
    error InvalidSignatureLength(uint256 length);
    error NonCanonicalFieldElement();
    error InfinityPoint();
    error InvalidGroupKey();

    // ---------------------------------------------------------------- precompiles (EIP-2537, EIP-198)
    // Gas forwarded to each precompile is bounded (SPEC §4.4): a failing precompile consumes all
    // gas it was given, so an invalid input must not burn the caller's whole budget. Each cap is
    // several times the Prague/Osaka nominal cost, so a moderate repricing still fits.
    uint256 internal constant SHA256_GAS = 5_000; // nominal 60 + 12 per word
    uint256 internal constant MODEXP_GAS = 10_000; // nominal 200 (EIP-2565) / 500 (EIP-7883)
    uint256 internal constant G1ADD_GAS = 3_000; // nominal 375
    uint256 internal constant G2MSM1_GAS = 60_000; // nominal 22,500 for one pair
    uint256 internal constant PAIRING2_GAS = 250_000; // nominal 37,700 + 2 * 32,600
    uint256 internal constant MAP_FP_TO_G1_GAS = 20_000; // nominal 5,500
    address internal constant SHA256_PRECOMPILE = address(0x02);
    address internal constant MODEXP_PRECOMPILE = address(0x05);
    address internal constant G1ADD_PRECOMPILE = address(0x0b);
    address internal constant G2MSM_PRECOMPILE = address(0x0e);
    address internal constant PAIRING_PRECOMPILE = address(0x0f);
    address internal constant MAP_FP_TO_G1_PRECOMPILE = address(0x10);

    // ---------------------------------------------------------------- field constants
    /// @dev p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    /// @dev (p - 1) / 2: y is the "larger" root (sign bit set) when y > (p - 1) / 2.
    uint256 internal constant HALF_P_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 internal constant HALF_P_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;

    // ---------------------------------------------------------------- generators (EIP-2537 appendix)
    uint256 internal constant G1_GEN_X_HI = 0x17f1d3a73197d7942695638c4fa9ac0f;
    uint256 internal constant G1_GEN_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint256 internal constant G1_GEN_Y_HI = 0x08b3f481e3aaa0f1a09e30ed741d8ae4;
    uint256 internal constant G1_GEN_Y_LO = 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

    /// @dev Negated G2 generator (-G2 = (x, p - y)), so that the pairing check
    ///      e(sig, -G2) * e(H(M), PK) == 1 needs no runtime negation.
    uint256 internal constant NEG_G2_X0_HI = 0x024aa2b2f08f0a91260805272dc51051;
    uint256 internal constant NEG_G2_X0_LO = 0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    uint256 internal constant NEG_G2_X1_HI = 0x13e02b6052719f607dacd3a088274f65;
    uint256 internal constant NEG_G2_X1_LO = 0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    uint256 internal constant NEG_G2_Y0_HI = 0x0d1b3cc2c7027888be51d9ef691d77bc;
    uint256 internal constant NEG_G2_Y0_LO = 0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa;
    uint256 internal constant NEG_G2_Y1_HI = 0x13fa4d4a0ad8b1ce186ed5061789213d;
    uint256 internal constant NEG_G2_Y1_LO = 0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed;

    // ---------------------------------------------------------------- field element checks

    /// @notice True when `(hi, lo)` is a canonical field element: zero upper 128 bits and value < p.
    function isCanonicalFp(uint256 hi, uint256 lo) internal pure returns (bool) {
        if (hi >> 128 != 0) return false;
        return hi < P_HI || (hi == P_HI && lo < P_LO);
    }

    /// @notice True when y > (p - 1) / 2, i.e. the compressed-encoding sign bit must be set.
    function isLargerRoot(uint256 yHi, uint256 yLo) internal pure returns (bool) {
        return yHi > HALF_P_HI || (yHi == HALF_P_HI && yLo > HALF_P_LO);
    }

    // ---------------------------------------------------------------- G1 submit form

    /// @notice Parses the 96-byte submit form into the 128-byte EIP form, enforcing exact length,
    ///         canonical coordinates and non-infinity. On-curve and subgroup membership are not
    ///         established here; the pairing precompile enforces both (SPEC §4.3).
    /// @return eip 128-byte EIP-2537 G1 encoding of the same point.
    function parseAffineG1(bytes calldata affine) internal pure returns (bytes memory eip) {
        if (affine.length != 96) revert InvalidSignatureLength(affine.length);
        eip = new bytes(128);
        assembly ("memory-safe") {
            let dst := add(eip, 32)
            mstore(dst, 0)
            calldatacopy(add(dst, 16), affine.offset, 48)
            mstore(add(dst, 64), 0)
            calldatacopy(add(dst, 80), add(affine.offset, 48), 48)
        }
        (uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo) = loadG1(eip);
        if (!isCanonicalFp(xHi, xLo) || !isCanonicalFp(yHi, yLo)) revert NonCanonicalFieldElement();
        if (xHi == 0 && xLo == 0 && yHi == 0 && yLo == 0) revert InfinityPoint();
    }

    /// @notice Loads the four words of a 128-byte EIP-form G1 point.
    function loadG1(bytes memory eip) internal pure returns (uint256 xHi, uint256 xLo, uint256 yHi, uint256 yLo) {
        assembly ("memory-safe") {
            let p := add(eip, 32)
            xHi := mload(p)
            xLo := mload(add(p, 32))
            yHi := mload(add(p, 64))
            yLo := mload(add(p, 96))
        }
    }

    /// @notice Rebuilds the standard 48-byte compressed encoding of a canonical, non-infinity
    ///         affine G1 point given in EIP form. This is the only input to the output hash.
    function compressG1(bytes memory eip) internal pure returns (bytes memory compressed) {
        (uint256 xHi,, uint256 yHi, uint256 yLo) = loadG1(eip);
        uint256 flags = isLargerRoot(yHi, yLo) ? 0xa0 : 0x80;
        compressed = new bytes(48);
        assembly ("memory-safe") {
            let src := add(eip, 48) // start of the 48-byte x within pad64(x)
            let dst := add(compressed, 32)
            mstore(dst, mload(src))
            mstore(add(dst, 32), mload(add(src, 32)))
            // top byte of x is below 0x20 because x < p < 2^381, so OR equals ADD here
            mstore8(dst, or(byte(16, xHi), flags))
        }
    }

    // ---------------------------------------------------------------- precompile calls

    /// @notice STATICCALLs `precompile` with at most `gasLimit` gas and requires success with
    ///         exactly `outLen` return bytes.
    function callPrecompile(address precompile, bytes memory input, uint256 outLen, uint256 gasLimit)
        internal
        view
        returns (bytes memory out)
    {
        bool ok;
        (ok, out) = tryPrecompile(precompile, input, outLen, gasLimit);
        if (!ok) revert PrecompileFailure(precompile);
    }

    /// @notice SHA-256 through the precompile with an exact 32-byte return check.
    function sha256Strict(bytes memory data) internal view returns (bytes32 digest) {
        bytes memory out = callPrecompile(SHA256_PRECOMPILE, data, 32, SHA256_GAS);
        assembly ("memory-safe") {
            digest := mload(add(out, 32))
        }
    }

    /// @notice Reduces a 64-byte big-endian integer modulo p through MODEXP (exponent 1) and
    ///         returns it as a 64-byte padded field element.
    function reduceToFp(bytes memory wide, uint256 offset) internal view returns (bytes memory padded) {
        require(wide.length >= offset + 64, "BLS12381: short input");
        bytes memory input = new bytes(96 + 64 + 1 + 48);
        assembly ("memory-safe") {
            let p := add(input, 32)
            mstore(p, 64) // base length
            mstore(add(p, 32), 1) // exponent length
            mstore(add(p, 64), 48) // modulus length
            let src := add(add(wide, 32), offset)
            mstore(add(p, 96), mload(src))
            mstore(add(p, 128), mload(add(src, 32)))
            mstore8(add(p, 160), 1) // exponent = 1
            // modulus p as 48 bytes: P_HI occupies the low 16 bytes of its word
            mstore(add(p, 161), shl(128, P_HI))
            mstore(add(p, 177), P_LO)
        }
        bytes memory reduced = callPrecompile(MODEXP_PRECOMPILE, input, 48, MODEXP_GAS);
        padded = new bytes(64);
        assembly ("memory-safe") {
            let d := add(padded, 32)
            mstore(d, 0)
            mstore(add(d, 16), mload(add(reduced, 32))) // bytes 16..48 = reduced[0..32]
            mstore(add(d, 32), mload(add(reduced, 48))) // bytes 32..64 = reduced[16..48]
        }
    }

    /// @notice MAP_FP_TO_G1 on a 64-byte padded canonical field element; returns the 128-byte point.
    function mapFpToG1(bytes memory paddedFp) internal view returns (bytes memory point) {
        require(paddedFp.length == 64, "BLS12381: bad fp length");
        point = callPrecompile(MAP_FP_TO_G1_PRECOMPILE, paddedFp, 128, MAP_FP_TO_G1_GAS);
    }

    /// @notice G1ADD of two 128-byte EIP-form points.
    function addG1(bytes memory a, bytes memory b) internal view returns (bytes memory sum) {
        require(a.length == 128 && b.length == 128, "BLS12381: bad g1 length");
        sum = callPrecompile(G1ADD_PRECOMPILE, bytes.concat(a, b), 128, G1ADD_GAS);
    }

    /// @notice Pairing check e(sig, -G2) * e(hm, pk) == 1, i.e. e(sig, G2) == e(hm, pk).
    ///         The precompile rejects non-canonical, off-curve and non-subgroup inputs and
    ///         returns exactly 32 bytes equal to 1 on success.
    /// @param sig 128-byte EIP-form G1 signature
    /// @param hm 128-byte EIP-form hash-to-curve point
    /// @param pk 256-byte EIP-form G2 group key
    function pairingCheck(bytes memory sig, bytes memory hm, bytes memory pk) internal view returns (bool) {
        require(sig.length == 128 && hm.length == 128 && pk.length == 256, "BLS12381: bad pairing input");
        bytes memory input = new bytes(768);
        assembly ("memory-safe") {
            let p := add(input, 32)
            mcopy(p, add(sig, 32), 128)
            mstore(add(p, 128), NEG_G2_X0_HI)
            mstore(add(p, 160), NEG_G2_X0_LO)
            mstore(add(p, 192), NEG_G2_X1_HI)
            mstore(add(p, 224), NEG_G2_X1_LO)
            mstore(add(p, 256), NEG_G2_Y0_HI)
            mstore(add(p, 288), NEG_G2_Y0_LO)
            mstore(add(p, 320), NEG_G2_Y1_HI)
            mstore(add(p, 352), NEG_G2_Y1_LO)
            mcopy(add(p, 384), add(hm, 32), 128)
            mcopy(add(p, 512), add(pk, 32), 256)
        }
        bytes memory out = callPrecompile(PAIRING_PRECOMPILE, input, 32, PAIRING2_GAS);
        uint256 result;
        assembly ("memory-safe") {
            result := mload(add(out, 32))
        }
        return result == 1;
    }

    /// @notice Validates a 256-byte EIP-form G2 point as a group key: canonical coefficients,
    ///         not infinity, on the twist and in the prime-order subgroup. Subgroup membership is
    ///         established by G2MSM with scalar one, whose output must equal the input.
    function validateGroupKey(bytes memory pk) internal view {
        if (pk.length != 256) revert InvalidGroupKey();
        bool allZero = true;
        for (uint256 i = 0; i < 8; i++) {
            uint256 hi;
            uint256 lo;
            assembly ("memory-safe") {
                hi := mload(add(add(pk, 32), mul(i, 32)))
            }
            if (i % 2 == 0) {
                assembly ("memory-safe") {
                    lo := mload(add(add(pk, 64), mul(i, 32)))
                }
                if (!isCanonicalFp(hi, lo)) revert InvalidGroupKey();
            }
            if (hi != 0) allZero = false;
        }
        if (allZero) revert InvalidGroupKey();
        bytes memory input = new bytes(288);
        assembly ("memory-safe") {
            mcopy(add(input, 32), add(pk, 32), 256)
            mstore(add(input, 288), 1)
        }
        (bool ok, bytes memory out) = tryPrecompile(G2MSM_PRECOMPILE, input, 256, G2MSM1_GAS);
        // A failed call covers off-twist and non-subgroup points as well as a missing precompile.
        if (!ok || keccak256(out) != keccak256(pk)) revert InvalidGroupKey();
    }

    /// @notice Non-reverting variant of `callPrecompile`: `ok` is false on failure or a wrong length.
    function tryPrecompile(address precompile, bytes memory input, uint256 outLen, uint256 gasLimit)
        internal
        view
        returns (bool ok, bytes memory out)
    {
        out = new bytes(outLen);
        uint256 returned;
        assembly ("memory-safe") {
            ok := staticcall(gasLimit, precompile, add(input, 32), mload(input), add(out, 32), outLen)
            returned := returndatasize()
        }
        ok = ok && returned == outLen;
    }

    /// @notice 128-byte EIP form of the G1 generator (used by genesis self-tests).
    function g1Generator() internal pure returns (bytes memory g) {
        g = new bytes(128);
        assembly ("memory-safe") {
            mstore(add(g, 32), G1_GEN_X_HI)
            mstore(add(g, 64), G1_GEN_X_LO)
            mstore(add(g, 96), G1_GEN_Y_HI)
            mstore(add(g, 128), G1_GEN_Y_LO)
        }
    }

    /// @notice 256-byte EIP form of the negated G2 generator.
    function negG2Generator() internal pure returns (bytes memory g) {
        g = new bytes(256);
        assembly ("memory-safe") {
            mstore(add(g, 32), NEG_G2_X0_HI)
            mstore(add(g, 64), NEG_G2_X0_LO)
            mstore(add(g, 96), NEG_G2_X1_HI)
            mstore(add(g, 128), NEG_G2_X1_LO)
            mstore(add(g, 160), NEG_G2_Y0_HI)
            mstore(add(g, 192), NEG_G2_Y0_LO)
            mstore(add(g, 224), NEG_G2_Y1_HI)
            mstore(add(g, 256), NEG_G2_Y1_LO)
        }
    }
}
